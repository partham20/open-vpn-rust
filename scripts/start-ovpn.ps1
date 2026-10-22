<#
.SYNOPSIS
    Run ovpn (the portable OpenVPN client) in the background, with no window.

.DESCRIPTION
    Without a switch (or with -Start), connects in the background: ovpn.exe
    runs hidden and logs to C:\ProgramData\ovpn\ovpn.log. The first time, it
    asks for your OpenVPN username and password and keeps them in
    C:\ProgramData\ovpn\auth.txt, which only Administrators can read.

    -Stop disconnects. -Status shows whether it's running and the last log
    lines. -Login asks for the username and password again.

    -Install also connects at every boot, before anyone signs in, and
    reconnects if ovpn stops. It copies ovpn.exe, this script and the .ovpn
    file to C:\Program Files\ovpn. Run -Install again to switch servers or
    update ovpn.exe. -Uninstall removes it (the saved login stays until you
    delete C:\ProgramData\ovpn).

    ovpn.exe and the .ovpn file are looked for next to this script, then in
    your Downloads folder. If there are several .ovpn files, the newest is
    used unless you pass -Config. Every mode asks for Administrator rights if
    it doesn't have them.

.EXAMPLE
    .\start-ovpn.ps1                 # connect in the background

.EXAMPLE
    .\start-ovpn.ps1 -Config '.\Windscribe-Mumbai-TCP.ovpn'

.EXAMPLE
    .\start-ovpn.ps1 -Status

.EXAMPLE
    .\start-ovpn.ps1 -Stop
#>
[CmdletBinding(DefaultParameterSetName = 'Start')]
param(
    # The .ovpn file to use (default: the newest one next to ovpn.exe).
    [string]$Config = '',
    # Folder that holds ovpn.exe.
    [string]$OvpnDir = '',

    [Parameter(ParameterSetName = 'Start')][switch]$Start,
    [Parameter(ParameterSetName = 'Stop')][switch]$Stop,
    [Parameter(ParameterSetName = 'Status')][switch]$Status,
    # Ask for the username and password again, then connect.
    [Parameter(ParameterSetName = 'Login')][switch]$Login,
    # Connect at every boot and keep reconnecting.
    [Parameter(ParameterSetName = 'Install')][switch]$Install,
    [Parameter(ParameterSetName = 'Uninstall')][switch]$Uninstall,
    # Used by the startup task: keep ovpn running.
    [Parameter(ParameterSetName = 'Background')][switch]$Background,

    # Set when this script re-launched itself as Administrator.
    [switch]$Elevated
)

$ErrorActionPreference = 'Stop'

$TaskName = 'ovpn'
$InstallDir = Join-Path $env:ProgramFiles 'ovpn'
$DataDir = Join-Path $env:ProgramData 'ovpn'
$AuthFile = Join-Path $DataDir 'auth.txt'
$LogFile = Join-Path $DataDir 'ovpn.log'
# The config the startup task uses.
$TaskConfig = Join-Path $DataDir 'config.ovpn'

function Wait-BeforeClosing {
    # A window opened by the elevation prompt would otherwise vanish before
    # its output can be read.
    if ($Elevated) { Read-Host "`nPress Enter to close" | Out-Null }
}

function Fail([string]$msg) {
    Write-Host $msg -ForegroundColor Red
    Wait-BeforeClosing
    exit 1
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    # Pass paths explicitly: an elevated session may see a different profile.
    $here = if ($OvpnDir) { $OvpnDir } else { $PSScriptRoot }
    $argList = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', "`"$PSCommandPath`"",
        '-OvpnDir', "`"$here`"",
        '-Elevated'
    )
    if ($Config) { $argList += @('-Config', "`"$((Resolve-Path $Config).Path)`"") }
    $argList += "-$($PSCmdlet.ParameterSetName)"
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList
    return
}

function Find-Exe {
    $dirs = @($OvpnDir, $PSScriptRoot, (Join-Path $env:USERPROFILE 'Downloads')) | Where-Object { $_ }
    foreach ($d in $dirs) {
        $p = Join-Path $d 'ovpn.exe'
        if (Test-Path $p) { return (Resolve-Path $p).Path }
    }
    Fail ("ovpn.exe not found (looked in: $($dirs -join ', ')).`n" +
          'Download it from https://github.com/partham20/open-vpn-rust/releases/latest')
}

function Find-Config([string]$exeDir) {
    if ($Config) {
        if (-not (Test-Path $Config)) { Fail "Config file not found: $Config" }
        return (Resolve-Path $Config).Path
    }
    $dirs = @($exeDir, $PSScriptRoot, (Join-Path $env:USERPROFILE 'Downloads')) | Select-Object -Unique
    foreach ($d in $dirs) {
        $files = @(Get-ChildItem -Path $d -Filter '*.ovpn' -File -ErrorAction SilentlyContinue |
                   Sort-Object LastWriteTime -Descending)
        if ($files.Count -gt 0) {
            if ($files.Count -gt 1) {
                Write-Host "Several .ovpn files in $d; using the newest: $($files[0].Name) (pass -Config to choose)."
            }
            return $files[0].FullName
        }
    }
    Fail 'No .ovpn file found. Put your Windscribe TCP config next to ovpn.exe, or pass -Config.'
}

function Initialize-DataDir {
    if (-not (Test-Path $DataDir)) {
        New-Item -ItemType Directory -Path $DataDir | Out-Null
    }
    # The saved login and log: SYSTEM and Administrators only, nothing inherited.
    & icacls.exe $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed to restrict $DataDir" }
}

function Save-Login {
    Write-Host 'Enter your OpenVPN credentials. For Windscribe these come from the config generator page'
    Write-Host '("Get Credentials"); they are not your account login.'
    $user = Read-Host 'Username'
    $sec = Read-Host 'Password' -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try { $pass = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    if (-not $user) { Fail 'No username given.' }
    [IO.File]::WriteAllLines($AuthFile, [string[]]@($user.Trim(), $pass))
    Write-Host "Saved to $AuthFile (readable by Administrators only)."
}

function Get-Ovpn {
    Get-Process -Name 'ovpn' -ErrorAction SilentlyContinue
}

function Stop-Ovpn {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName
    }
    $procs = Get-Ovpn
    if ($procs) {
        $procs | Stop-Process -Force
        # Wait until ovpn.exe and wintun.dll can be replaced.
        $procs | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
    }
}

function Limit-Log {
    if ((Test-Path $LogFile) -and (Get-Item $LogFile).Length -gt 5MB) {
        Move-Item -Force $LogFile "$LogFile.old"
    }
}

function Show-LogTail([int]$lines = 15) {
    if (Test-Path $LogFile) {
        Write-Host "`nLast lines of $LogFile`:"
        Get-Content $LogFile -Tail $lines
    }
}

switch ($PSCmdlet.ParameterSetName) {

'Background' {
    # Run by the startup task as SYSTEM from $InstallDir.
    $exe = Join-Path $PSScriptRoot 'ovpn.exe'
    while ((Test-Path $exe) -and (Test-Path $TaskConfig)) {
        Limit-Log
        # ovpn reconnects by itself once it is up. It exits on errors that
        # retrying won't fix (a wrong password, a bad config), so wait a
        # while before trying again.
        & $exe $TaskConfig --auth-file $AuthFile --log-file $LogFile
        Start-Sleep -Seconds 30
    }
    exit 1
}

{ $_ -in 'Start', 'Login' } {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task -and $task.State -eq 'Running') {
        Write-Host 'ovpn already runs in the background from the startup task. Use -Status, -Stop or -Uninstall.'
        Wait-BeforeClosing
        return
    }
    if (Get-Ovpn) {
        Write-Host 'ovpn is already running. Use -Status to check on it, or -Stop to disconnect.'
        Wait-BeforeClosing
        return
    }
    $exe = Find-Exe
    $cfg = Find-Config (Split-Path $exe)
    Initialize-DataDir
    if ($Login -or -not (Test-Path $AuthFile)) { Save-Login }
    Limit-Log

    $offset = if (Test-Path $LogFile) { (Get-Item $LogFile).Length } else { 0 }
    Get-ChildItem (Split-Path $exe) -Filter 'ovpn.exe' | Unblock-File
    $proc = Start-Process -FilePath $exe -WindowStyle Hidden -PassThru `
        -WorkingDirectory (Split-Path $exe) `
        -ArgumentList @("`"$cfg`"", '--auth-file', "`"$AuthFile`"", '--log-file', "`"$LogFile`"")
    Write-Host "Connecting with $(Split-Path $cfg -Leaf)..."

    # Wait for "connected" in the new part of the log, or for ovpn to exit.
    $deadline = (Get-Date).AddSeconds(30)
    $result = 'timeout'
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        $new = ''
        if (Test-Path $LogFile) {
            $fs = [IO.File]::Open($LogFile, 'Open', 'Read', 'ReadWrite')
            try {
                [void]$fs.Seek($offset, 'Begin')
                $new = (New-Object IO.StreamReader($fs)).ReadToEnd()
            } finally { $fs.Dispose() }
        }
        if ($new -match 'INFO connected:') { $result = 'connected'; break }
        if ($proc.HasExited) { $result = 'exited'; break }
    }
    switch ($result) {
        'connected' {
            Write-Host "`nConnected. ovpn runs in the background (PID $($proc.Id)), with no window." -ForegroundColor Green
            Write-Host 'Disconnect with:  start-ovpn.ps1 -Stop'
            Write-Host 'Check on it with: start-ovpn.ps1 -Status'
        }
        'exited' {
            Write-Host "`novpn stopped:" -ForegroundColor Red
            Show-LogTail 8
            if ($new -match 'authentication failed') {
                Write-Host "`nRun start-ovpn.ps1 -Login to enter the username and password again."
            }
        }
        default {
            Write-Host "`nNot connected yet; ovpn keeps trying in the background (PID $($proc.Id))." -ForegroundColor Yellow
            Show-LogTail 8
        }
    }
    Wait-BeforeClosing
}

'Stop' {
    if (-not (Get-Ovpn)) {
        Write-Host 'ovpn is not running.'
    } else {
        Stop-Ovpn
        Write-Host 'Disconnected.' -ForegroundColor Green
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
            Write-Host 'The startup task will connect again at the next boot (-Uninstall removes it).'
        }
    }
    Wait-BeforeClosing
}

'Status' {
    $proc = Get-Ovpn
    if ($proc) {
        Write-Host "ovpn.exe: running (PID $($proc.Id -join ', '))" -ForegroundColor Green
    } else {
        Write-Host 'ovpn.exe: not running' -ForegroundColor Yellow
    }
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        $info = $task | Get-ScheduledTaskInfo
        Write-Host "Startup task: $($task.State), last started $($info.LastRunTime)"
    }
    Show-LogTail 20
    Wait-BeforeClosing
}

'Install' {
    $exe = Find-Exe
    $cfg = Find-Config (Split-Path $exe)
    Initialize-DataDir
    if (-not (Test-Path $AuthFile)) { Save-Login }

    Write-Host "Copying ovpn to $InstallDir..."
    Stop-Ovpn
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    if ((Split-Path $exe) -ne $InstallDir) {
        Copy-Item -Force $exe (Join-Path $InstallDir 'ovpn.exe')
    }
    if ($PSCommandPath -ne (Join-Path $InstallDir 'start-ovpn.ps1')) {
        Copy-Item -Force $PSCommandPath (Join-Path $InstallDir 'start-ovpn.ps1')
    }
    Get-ChildItem $InstallDir | Unblock-File
    if ($cfg -ne $TaskConfig) { Copy-Item -Force $cfg $TaskConfig }
    Write-Host "Server config: $(Split-Path $cfg -Leaf)"

    $taskScript = Join-Path $InstallDir 'start-ovpn.ps1'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -WorkingDirectory $InstallDir `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$taskScript`" -Background"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    # No time limit, run on battery, and restart the task itself if it dies.
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
        -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force `
        -Description 'ovpn: portable OpenVPN client (https://github.com/partham20/open-vpn-rust)' | Out-Null
    Start-ScheduledTask -TaskName $TaskName

    Write-Host "`nInstalled. ovpn is connecting in the background and will connect at every boot." -ForegroundColor Green
    Write-Host "Log: $LogFile"
    Write-Host 'Check on it with: start-ovpn.ps1 -Status'
    Write-Host 'Remove it with:   start-ovpn.ps1 -Uninstall'
    Wait-BeforeClosing
}

'Uninstall' {
    Write-Host 'Stopping ovpn and removing the startup task...'
    Stop-Ovpn
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }
    Remove-Item -Force $TaskConfig -ErrorAction SilentlyContinue
    Write-Host "`nUninstalled." -ForegroundColor Green
    Write-Host "Your saved login and the log are still in $DataDir. Delete that folder to remove them."
    Wait-BeforeClosing
}

}
