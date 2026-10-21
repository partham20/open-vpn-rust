//! rustls setup. OpenVPN servers are identified by the CA in the config,
//! not by DNS name, so the verifier checks the chain against that CA and
//! (optionally) `verify-x509-name`, but not the hostname.

use anyhow::{anyhow, bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, TrustAnchor, UnixTime};
use std::sync::Arc;

use crate::config::Config;

#[derive(Debug)]
struct OvpnVerifier {
    roots: Vec<TrustAnchor<'static>>,
    provider: Arc<CryptoProvider>,
    x509_name: Option<(String, String)>,
    require_server_eku: bool,
}

impl ServerCertVerifier for OvpnVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        for c in std::iter::once(end_entity).chain(intermediates) {
            if let Ok((_, x)) = x509_parser::parse_x509_certificate(c) {
                tracing::debug!("server cert: {} (issuer {})", x.subject(), x.issuer());
            }
        }
        let cert = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|e| rustls::Error::General(format!("bad server certificate: {e}")))?;
        // Like OpenVPN, only the server's own certificate is checked for
        // extended key usage (below); CA certificates in the chain often
        // carry none, which webpki's built-in policies would reject.
        cert.verify_for_usage(
            self.provider.signature_verification_algorithms.all,
            &self.roots,
            intermediates,
            now,
            AnyEku,
            None,
            None,
        )
        .map_err(|e| {
            rustls::Error::General(format!(
                "server certificate rejected (does the .ovpn's <ca> belong to this server?): {e:?}"
            ))
        })?;
        if self.require_server_eku {
            check_server_eku(end_entity).map_err(|e| rustls::Error::General(e.to_string()))?;
        }
        if let Some((name, kind)) = &self.x509_name {
            check_x509_name(end_entity, name, kind)
                .map_err(|e| rustls::Error::General(e.to_string()))?;
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Accepts any extended key usage on every certificate in the chain.
struct AnyEku;

impl webpki::ExtendedKeyUsageValidator for AnyEku {
    fn validate(&self, _: webpki::KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        Ok(())
    }
}

/// `remote-cert-tls server`: the server certificate must be meant for TLS
/// servers. If it has an EKU extension, that must include serverAuth; if it
/// has none, the old Netscape "SSL server" type is accepted too.
fn check_server_eku(der: &CertificateDer<'_>) -> Result<()> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(der).context("parsing server certificate")?;
    match cert.extended_key_usage() {
        Ok(Some(eku)) if eku.value.server_auth => Ok(()),
        Ok(Some(_)) => bail!(
            "the server certificate is not meant for VPN servers (no serverAuth key usage; remote-cert-tls server)"
        ),
        _ => {
            let ns_server = cert.extensions().iter().any(|e| {
                matches!(e.parsed_extension(),
                    x509_parser::extensions::ParsedExtension::NSCertType(t) if t.ssl_server())
            });
            if !ns_server {
                tracing::warn!(
                    "server certificate has no extended key usage; accepting it because it is signed by the config's CA"
                );
            }
            Ok(())
        }
    }
}

fn check_x509_name(der: &CertificateDer<'_>, want: &str, kind: &str) -> Result<()> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(der).context("parsing server certificate")?;
    let subject = cert.subject();
    let cn = subject
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .unwrap_or("");
    let ok = match kind {
        "name" => cn == want,
        "name-prefix" => cn.starts_with(want),
        _ => {
            // OpenVPN's "subject" form: "C=US, ST=..., CN=..." in its own
            // order; compare loosely by the set of RDN parts.
            let norm = |s: &str| {
                let mut v: Vec<String> = s.split(',').map(|p| p.trim().replace(' ', "")).collect();
                v.sort();
                v
            };
            norm(want) == norm(&subject.to_string()) || want == cn
        }
    };
    if !ok {
        bail!("server certificate name {cn:?} does not match verify-x509-name {want:?}");
    }
    Ok(())
}

pub fn client_config(cfg: &Config) -> Result<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = Vec::new();
    for cert in CertificateDer::pem_slice_iter(cfg.ca_pem.as_bytes()) {
        let cert = cert.context("parsing the CA certificate")?;
        let anchor = webpki::anchor_from_trusted_cert(&cert)
            .map_err(|e| anyhow!("unusable CA certificate: {e}"))?
            .to_owned();
        roots.push(anchor);
    }
    if roots.is_empty() {
        bail!("no certificates found in the CA block");
    }
    let verifier = Arc::new(OvpnVerifier {
        roots,
        provider: provider.clone(),
        x509_name: cfg.verify_x509_name.clone(),
        require_server_eku: cfg.remote_cert_tls_server,
    });
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let config = match (&cfg.cert_pem, &cfg.key_pem) {
        (Some(c), Some(k)) => {
            let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(c.as_bytes())
                .collect::<Result<_, _>>()
                .context("parsing the client certificate")?;
            let key =
                PrivateKeyDer::from_pem_slice(k.as_bytes()).context("parsing the client key")?;
            builder.with_client_auth_cert(chain, key)?
        }
        _ => builder.with_no_client_auth(),
    };
    Ok(Arc::new(config))
}
