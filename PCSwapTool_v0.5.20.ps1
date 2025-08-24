
<# 
    .SYNOPSIS
    PC Swap Tool (GUI) - Gather & Restore
    Version: 0.5.20 (2025-08-24)

.DESCRIPTION
    A WinForms GUI PowerShell tool to gather migration data from a Windows 10/11 machine,
    produce a technician report and a machine-readable manifest, and restore/apply that data
    to a replacement machine. Native Windows only.

.CHANGELOG
    0.5.10
      - Feature: Read default PDF and browser ProgIds from the new UserChoiceLatest registry keys when available (for ".pdf" and HTTP associations) and fall back to legacy UserChoice keys. This prevents defaults from appearing as MS Edge when Chrome/Adobe are set.
      - Bumped version and changelog accordingly.
      - Date: 2025-08-24

    0.5.11
      - Fix: Mapped drives enumeration now works under an elevated session.  Instead of relying on
        Get‑WmiObject Win32_LogicalDisk (which does not see non‑admin mapped drives when UAC
        filtering is in effect), a new Get‑MappedDrives helper uses the WScript.Network COM object
        and the HKCU:\Network registry key to gather network drive letter/path pairs.  This ensures
        mapped drives appear in the technician report even when the tool runs as administrator.
      - Version and changelog updated.
      - Date: 2025-08-24

    0.5.12
      - Fix: Corrected variable interpolation for network drive letters.  A colon appended to
        a variable inside a double‑quoted string was being misinterpreted by PowerShell’s
        parser.  Using the `${letter}:` syntax resolves the error (`InvalidVariableReferenceWithDrive`).
      - Date: 2025-08-24

    0.5.14
      - Feature: Added export and import of saved wireless network profiles.  During the gather
        phase, all WLAN profiles are exported using `netsh wlan export profile` into a
        `WirelessProfiles` folder under the repository, and their SSIDs are recorded in the
        manifest and technician report.  During the restore phase, these profiles are
        re‑imported using `netsh wlan add profile` after network configuration.  A new
        `Get-WlanProfileNames` helper lists profile names for logging, and `WirelessNetworks`
        appear under the Computer section in the manifest and report.
      - Improvement: The restore workflow now calls `Set-SwapInfoRoot` based on the selected
        manifest, ensuring repository‑dependent paths (like state.json) are set correctly on
        the target machine.
      - Date: 2025-08-24

    0.5.17
      - Feature: Added support for capturing Outlook account credentials during
        the gather phase and surfacing them during restore.  A new checkbox
        on the Gather tab allows the technician to decide whether to prompt
        for these credentials.  If checked, a secure dialog collects the
        email address and password which are stored in the manifest for
        restore use.  During restore, the technician is shown the stored
        credentials and Outlook is launched so the account can be added.
      - Feature: Added a checkbox to skip the profile copy.  When checked,
        the Copy‑UserProfile step is bypassed and the gather completes
        without copying the user’s profile data.  This is useful when
        re‑running the gather after the profile has already been copied.
      - Fix: Bumped version numbers and updated the changelog.
      - Date: 2025-08-24

    0.5.16
      - Fix: Corrected variable interpolation in network drive enumeration.  Previously
        a colon appended directly to a variable name could cause a
        `InvalidVariableReferenceWithDrive` parser error under certain PowerShell
        versions.  All occurrences now use the `${name}:` syntax to avoid
        misinterpretation.
      - Improvement: Ensured wireless network profiles are exported during the gather
        phase and imported during the restore phase.  Added logging of SSIDs in
        the technician report and manifest.  This enhancement allows seamless
        restoration of Wi‑Fi connectivity on the new machine.
      - Version bump and changelog update.
      - Date: 2025-08-24

    0.5.20
      - Feature: Added optional -Manifest command-line parameter.  When supplied, the script
        will use the specified manifest file for restore/resume operations instead of
        reading the ManifestPath from state.json.  This allows invoking the script
        directly with a manifest to complete restore operations without relying on
        intermediate state.  Scheduled tasks now include the -Manifest argument when
        resuming.
      - Enhancement: New-RunOnceResume and Register-UserResumeTask accept a ManifestPath
        parameter and append it to the PowerShell invocation string so that the
        manifest is always available during resume phases.
      - Misc: Bumped version and updated changelog.
      - Date: 2025-08-24
      - Feature: Gather tab now exposes the Skip Copy and Capture Outlook Credentials
        checkboxes in the UI.  These flags are honored in the gather workflow:
          • When Skip Copy is checked, the profile copy step is skipped and a summary
            message is recorded instead of calling Copy-UserProfile.
          • When Capture Outlook Credentials is checked, the technician is prompted
            for email/password via a secure dialog and the resulting object is stored
            in the manifest under OutlookSetupAccount.
      - Feature: During restore (both immediate and resume), if OutlookSetupAccount is
        present in the manifest, Show-OutlookAccountForRestore is invoked to display
        the stored credentials and guide the technician through adding the account.
      - Fix: Deferred initialization of repository paths until the destination is chosen;
        no early assignment of SwapInfoRoot or related variables occurs prior to clicking
        Start Gather, eliminating null-path errors.
      - Version number bumped and changelog updated.
      - Date: 2025-08-24

    0.5.9
      - Fix: Updated call to Set-SwapInfoRoot to use -RepoRoot parameter when building the repository path.
      - Fix: Ensured repository initialization occurs only after the technician selects a destination and clicks Start GATHER.
      - Fix: Removed remaining early assignments and stray closing parentheses that caused syntax errors.
      - Version bump and changelog update.
      - Date: 2025-08-24

    0.5.8
      - Fix: Deferred all repository globals ($SwapInfoRoot, $StatePath, $DeregListPath, $LogPath) until Start GATHER.
      - Fix: Repository created before Chrome export; no Desktop fallback anywhere.
      - Fix: Removed stray '))' syntax and null-Join-Path errors.
      - Date: 2025-08-24

    0.5.7
      - Fix: Ensure repository (PC_SWAP_INFO) is created under the chosen destination BEFORE Chrome export.
      - Fix: Removed Desktop fallback; all artifacts go under <Dest>\<HOST>_<DD-MM-YYYY>\PC_SWAP_INFO.
      - Maintenance: Reintroduced Set-SwapInfoRoot and reordered Gather flow.
      - Date: 2025-08-24

    0.5.6
      - Refactor: Program inventory made StrictMode-safe (no direct $p.Property).
      - Cleanup: Removed nested Get-RegPrograms; use Get-InstalledProgramsStrictSafe.
      - Fix: Retain Chrome.exe path preference (Program Files → x86 → LocalAppData → HKLM App Paths).
      - Date: 2025-08-24

    0.5.1
      - FIX: Moved [CmdletBinding()] + param() to the top of the script (PowerShell requirement).
      - FIX: All Write-Log calls now use named params (-Message/-Level) to avoid parsing ambiguity.
      - Keeps 0.5.0 features (local-user creation + user-context resume, profile restore, etc.).

    0.5.0
      - Restore: create local user (when not joining a domain), prompt for password & optional admin.
      - Restore resumes in user context to finish profile copy & HKCU items.
      - Restore: Profile source ROOT picker and auto-detect OLDHOST_DD-MM-YYYY.
      - Copy flags: /COPY:DAT /DCOPY:DAT everywhere (no Owner/SACL across SMB); add /SEC only for local NTFS.
      - Gather: profile copy path now uses HOSTNAME_DD-MM-YYYY.
      - Date-stamped folder path fix and robust logging.

.NOTES
    Requirements:
      - PowerShell 5.1, run as admin.
    Limitations (intentional):
      - Default apps cannot be set silently per-user; we record ProgIDs and open Settings.
      - Chrome password export guided via Chrome UI (Windows auth prompt appears).

#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$Resume,
    [switch]$ResumeUser,
    [string]$LogoPath,
    [string]$Manifest
)

Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ------------------------------- Globals -------------------------------------
$ProgramVersion = '0.5.20'
$TodayStamp     = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$Desktop        = [Environment]::GetFolderPath('Desktop')
$SwapInfoRoot   = $null
$ManifestName   = 'manifest.json'
$ReportName     = "technician_report_$TodayStamp.txt"
$LogPath        = $null
$StatePath      = $null
$DeregListPath = $null
$ChromeCsvName  = 'Chrome Passwords.csv'
$WallpaperName  = 'TranscodedWallpaper'

# If a manifest path is supplied on the command line, it will be captured here and used
# during resume phases instead of reading state.json.  This allows the restore flow
# to run directly against a specific manifest without relying on the interim state file.
$ManifestOverride = $Manifest

# Holds Outlook setup credentials captured during Gather.  Populated by
# Prompt-OutlookAccount when the technician chooses to capture credentials.
$script:OutlookSetupCred = $null

# (Repo created at gather time after destination selection)

# -------------- Logging helpers ----------------
$script:LogSubscribers = @()




function Ensure-Repository {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$BasePath,
        [switch]$OpenFolder
    )
    if (-not (Test-Path $BasePath)) {
        [System.Windows.Forms.MessageBox]::Show("Path not found: $BasePath","Path Error",'OK','Error') | Out-Null
        return $null
    }
    $dateStr = Get-Date -Format 'dd-MM-yyyy'
    $repo    = Join-Path $BasePath ("{0}_{1}" -f $env:COMPUTERNAME,$dateStr)
    $root    = Join-Path $repo 'PC_SWAP_INFO'
    Set-SwapInfoRoot -RepoRoot $root
    if ($OpenFolder) { Start-Process explorer.exe $root | Out-Null }
    return $root
}


function Set-SwapInfoRoot {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$RepoRoot)
    $script:SwapInfoRoot = $RepoRoot
    if (-not (Test-Path $script:SwapInfoRoot)) {
        New-Item -ItemType Directory -Path $script:SwapInfoRoot -Force | Out-Null
    }
    $script:StatePath     = Join-Path $script:SwapInfoRoot 'state.json'
    $script:DeregListPath = Join-Path $script:SwapInfoRoot 'deregistration-checklist.json'
    $script:LogPath       = Join-Path $script:SwapInfoRoot ("pcswap_{0}.log" -f (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'))
    try { Write-Log -Message "SwapInfoRoot set: $script:SwapInfoRoot" } catch {}
}



function Get-InstalledProgramsStrictSafe {
    $hives = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $items = @()
    foreach ($h in $hives) {
        if (-not (Test-Path $h)) { continue }
        Get-ChildItem -Path $h -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                if (-not $props) { return }
                $get = {
                    param($o,$n)
                    $p = $o.PSObject.Properties[$n]
                    if ($p) { $p.Value } else { $null }
                }
                $dn = & $get $props 'DisplayName'
                if ([string]::IsNullOrWhiteSpace($dn)) { return }

                $sc = & $get $props 'SystemComponent'
                $rt = & $get $props 'ReleaseType'
                if (($sc -ne $null -and [int]$sc -eq 1) -or ($rt -ne $null -and $rt -like '*Update*')) { return }

                $dv  = & $get $props 'DisplayVersion'
                $idr = & $get $props 'InstallDate'
                $il  = & $get $props 'InstallLocation'
                $pb  = & $get $props 'Publisher'
                $un  = & $get $props 'UninstallString'

                $id = $null
                if ($idr) {
                    try {
                        $s = [string]$idr
                        if ($s -match '^\d{8}$') {
                            $id = [datetime]::ParseExact($s,'yyyyMMdd',$null).ToString('yyyy-MM-dd')
                        } else {
                            $id = (Get-Date $idr).ToString('yyyy-MM-dd')
                        }
                    } catch { $id = $null }
                }

                $items += [PSCustomObject]@{
                    Name         = $dn
                    Version      = $dv
                    InstallDate  = $id
                    InstallDir   = $il
                    Publisher    = $pb
                    UninstallStr = $un
                }
            } catch { }
        }
    }
    $items | Sort-Object Name, Version, InstallDir -Unique
}

function Get-MappedDrives {
    # Enumerate network drives even from an elevated session.  First, use the WScript.Network
    # COM object to list currently mapped drives, then supplement with persistent
    # connections stored under HKCU:\Network.  Returned objects contain DeviceID and
    # ProviderName properties so they align with the existing report structure.  VolumeName
    # is left $null since that information is generally not available via these APIs.
    $drives = @()
    # WScript.Network enumeration
    try {
        $ws = New-Object -ComObject WScript.Network
        $col = $ws.EnumNetworkDrives()
        for ($i = 0; $i -lt $col.Count; $i += 2) {
            $drv  = $col.Item($i)
            $path = $col.Item($i + 1)
            if (-not [string]::IsNullOrWhiteSpace($drv)) {
                $drives += [PSCustomObject]@{
                    DeviceID     = $drv
                    ProviderName = $path
                    VolumeName   = $null
                }
            }
        }
    } catch {
        # COM enumeration may fail if WScript is unavailable; log and continue
        Write-Log -Message "WScript.Network enumeration failed: $($_)" -Level 'WARN'
    }
    # HKCU:\Network persistent mapped drives
    try {
        $networkKey = 'HKCU:\\Network'
        if (Test-Path $networkKey) {
            Get-ChildItem -Path $networkKey -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $props  = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                    $remote = $null
                    $pRemote = $props.PSObject.Properties['RemotePath']
                    if ($pRemote) { $remote = $pRemote.Value }
                    $letter = $_.PSChildName
                    if ($letter) {
                        # Ensure the colon is appended safely; use ${letter} to avoid $letter: being
                        # interpreted as a malformed variable.  Append a colon only if not already present.
                        $dev = if ($letter -match ':$') { $letter } else { "${letter}:" }
                        $drives += [PSCustomObject]@{
                            DeviceID     = $dev
                            ProviderName = $remote
                            VolumeName   = $null
                        }
                    }
                } catch {}
            }
        }
    } catch {
        Write-Log -Message "HKCU:\\Network enumeration failed: $($_)" -Level 'WARN'
    }
    # Deduplicate by drive letter (case-insensitive)
    return $drives | Sort-Object DeviceID -Unique
}

# Export all saved Wi‑Fi profiles to XML files under the repository.  Returns $true on
# success or $false on failure.  The profiles are exported in clear form so that they
# can be restored later.  Existing XML files are removed first.
function Export-WlanProfiles {
    try {
        if (-not $SwapInfoRoot) { Write-Log -Message "SwapInfoRoot not set; cannot export WLAN profiles." -Level 'WARN'; return $false }
        $dest = Join-Path $SwapInfoRoot 'WirelessProfiles'
        if (-not (Test-Path $dest)) { New-Item -ItemType Directory -Path $dest -Force | Out-Null }
        # Remove any previous exported profiles to avoid duplicates
        Get-ChildItem -Path $dest -Filter '*.xml' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        $quoted = "`"$dest`"" # wrap path in quotes for netsh
        # Use Start-Process to run netsh with arguments.  Use quotes around folder path to handle spaces.
        Start-Process -FilePath netsh.exe -ArgumentList @('wlan','export','profile',"folder=$quoted",'key=clear') -Wait -NoNewWindow | Out-Null
        Write-Log -Message "Exported wireless profiles to $dest"
        return $true
    } catch {
        Write-Log -Message "Export wireless profiles failed: $($_)" -Level 'WARN'
        return $false
    }
}

# List SSIDs of all saved Wi‑Fi profiles.  Uses netsh wlan show profiles to parse
# profile names.  Returns an array of strings.  Errors are logged but do not throw.
function Get-WlanProfileNames {
    $names = @()
    try {
        $lines = & netsh.exe wlan show profiles | Out-String -Stream
        foreach ($line in $lines) {
            if ($line -match 'All User Profile\s*:\s*(.+)') {
                $names += $Matches[1].Trim()
            }
        }
    } catch {
        Write-Log -Message "Get-WlanProfileNames failed: $($_)" -Level 'WARN'
    }
    return $names
}

# Import previously exported Wi‑Fi profiles from the given folder.  Each XML file
# under the folder is added using netsh wlan add profile filename=...
function Import-WlanProfiles {
    param([string]$ProfileFolder)
    if (-not (Test-Path $ProfileFolder)) {
        Write-Log -Message "Wireless profiles folder missing: $ProfileFolder" -Level 'WARN'
        return $false
    }
    $success = $true
    try {
        Get-ChildItem -Path $ProfileFolder -Filter '*.xml' -ErrorAction SilentlyContinue | ForEach-Object {
            $file = $_.FullName
            try {
                Start-Process -FilePath netsh.exe -ArgumentList @('wlan','add','profile',"filename=`"$file`"","user=all") -Wait -NoNewWindow | Out-Null
                Write-Log -Message "Imported wireless profile $($_.Name)"
            } catch {
                Write-Log -Message "Failed to import wireless profile $($_.Name): $($_)" -Level 'ERROR'
                $success = $false
            }
        }
    } catch {
        Write-Log -Message "Import-WlanProfiles failed: $($_)" -Level 'ERROR'
        return $false
    }
    return $success
}


function Add-LogSubscriber { param([ScriptBlock]$Sink) $script:LogSubscribers += $Sink }

function Write-Log {
    param([string]$Message,[ValidateSet('INFO','WARN','ERROR')]$Level='INFO')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[{0}][{1}] {2}" -f $ts,$Level,$Message
    try {
        $target = $script:LogPath
        if ([string]::IsNullOrWhiteSpace($target)) {
            $target = Join-Path $env:TEMP ("pcswap_{0}.log" -f (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'))
        }
        $dir = Split-Path -Parent $target
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -Path $target -Value $line -Encoding UTF8
    } catch {
        try { Write-Host $line } catch {}
    }
    # Broadcast the line to any registered log subscribers so the GUI can display it.
    foreach ($sink in $script:LogSubscribers) {
        try { & $sink $line } catch { }
    }
}


# ------------------- Utility -------------------
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
function Ensure-AdminOrWarn { if(-not (Test-Admin)){ Write-Log -Message "Not running elevated. Some operations may fail." -Level 'WARN' } }
function Save-Json { param($Object,[string]$Path,[int]$Depth=8) ($Object|ConvertTo-Json -Depth $Depth)|Set-Content -Path $Path -Encoding UTF8 }
function Load-Json { param([string]$Path) if(Test-Path $Path){ try{ (Get-Content -Raw -Path $Path|ConvertFrom-Json) }catch{ Write-Log -Message ("Parse JSON fail {0}: {1}" -f $Path, $_) -Level 'ERROR' } } }
function New-RunOnceResume {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ScriptPath,
        [string]$ManifestPath
    )
    # Build the command to run at next boot.  Always include -Resume; append -Manifest with path if provided.
    $args = '-Resume'
    if ($ManifestPath) { $args += " -Manifest \`"$ManifestPath\`"" }
    $cmd = "powershell.exe -ExecutionPolicy Bypass -NoProfile -File \`"$ScriptPath\`" $args"
    Write-Log -Message "Register RunOnce resume: $cmd"
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'PCSwapResume' -PropertyType String -Value $cmd -Force | Out-Null
}
function Select-FolderDialog { Add-Type -AssemblyName System.Windows.Forms | Out-Null; $dlg=New-Object System.Windows.Forms.FolderBrowserDialog; $dlg.Description="Select folder"; $dlg.ShowNewFolderButton=$true; if($dlg.ShowDialog() -eq 'OK'){ $dlg.SelectedPath } }
function Select-FileDialog { param([string]$Filter="All files (*.*)|*.*",[string]$Title="Select file")
    Add-Type -AssemblyName System.Windows.Forms | Out-Null; $dlg=New-Object System.Windows.Forms.OpenFileDialog; $dlg.Filter=$Filter; $dlg.Title=$Title; if($dlg.ShowDialog() -eq 'OK'){ $dlg.FileName }
}
function Copy-Safe { param([string]$Source,[string]$Dest)
    try{ if(Test-Path $Source){ New-Item -ItemType Directory -Path (Split-Path $Dest) -Force | Out-Null; Copy-Item $Source $Dest -Force -ErrorAction Stop; Write-Log -Message "Copied $(Split-Path -Leaf $Source) -> $Dest"; return $true } else { Write-Log -Message "Missing: $Source" -Level 'WARN' } }catch{ Write-Log -Message "Copy failed $Source -> $Dest : $_" -Level 'ERROR' } ; return $false
}
function Test-IsDomainJoined { try{ $cs=Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop; [bool]$cs.PartOfDomain }catch{ $false } }

# -------------- Data Collection ---------------
function Get-GeneralInfo {
    [PSCustomObject]@{
        ProgramVersion = $ProgramVersion
        CollectedAt    = (Get-Date).ToString('s')
        UserDomain     = $env:USERDOMAIN
        UserName       = $env:USERNAME
        ComputerName   = $env:COMPUTERNAME
    }
}
function Get-ComputerInfoPack {
    $netInfo=@()
    try{
        $nics=Get-NetIPConfiguration -ErrorAction Stop
        foreach($nic in $nics){
            if(-not $nic.IPv4Address){ continue }
            $ipv4=$nic.IPv4Address.IPAddress
            $gw=$nic.IPv4DefaultGateway.NextHop
            $dns=($nic.DnsServer.ServerAddresses -join ',')
            $mac=(Get-NetAdapter -InterfaceIndex $nic.InterfaceIndex).MacAddress
            $dhcp=(Get-WmiObject Win32_NetworkAdapterConfiguration | ? { $_.InterfaceIndex -eq $nic.InterfaceIndex }).DHCPEnabled
            $netInfo += [PSCustomObject]@{
                InterfaceAlias=$nic.InterfaceAlias; InterfaceIndex=$nic.InterfaceIndex
                IPv4Address=$ipv4; SubnetMask=$nic.IPv4Address.PrefixLength
                DefaultGateway=$gw; DnsServers=$dns; MacAddress=$mac; DhcpEnabled=[bool]$dhcp
            }
        }
    }catch{ Write-Log -Message "Get-NetIPConfiguration failed: $_" -Level 'ERROR' }
    $cs = Get-WmiObject -Class Win32_ComputerSystem
    # Enumerate saved Wi‑Fi networks (SSIDs) for logging.  Uses Get-WlanProfileNames helper.
    $wifi = @()
    try { $wifi = Get-WlanProfileNames } catch { Write-Log -Message "Wi-Fi enumeration failed: $($_)" -Level 'WARN' }
    $domain = $cs.Domain; $partOfDomain=[bool]$cs.PartOfDomain
    $printers=@(); try{
        if(Get-Command Get-Printer -ErrorAction SilentlyContinue){ $printers=Get-Printer | Select-Object Name,DriverName,PortName }
        else{ $printers=Get-WmiObject Win32_Printer | Select-Object Name,DriverName,PortName }
    }catch{ Write-Log -Message "Printers enum fail: $_" -Level 'ERROR' }
     [PSCustomObject]@{
        Hostname         = $env:COMPUTERNAME
        DomainName       = $domain
        PartOfDomain     = $partOfDomain
        NetworkAdapters  = $netInfo
        Printers         = $printers
        InstalledPrograms= (Get-InstalledProgramsStrictSafe)
        WirelessNetworks = $wifi
     }
}
function Get-UserInfoPack {
    # Use custom helper to enumerate network drives from both WScript.Network and HKCU:\Network.
    $mapped = @()
    try {
        $mapped = Get-MappedDrives
    } catch {
        Write-Log -Message "Mapped drives enumeration failed: $($_)" -Level 'ERROR'
    }
    $outlookAccounts=@(); try{
        $ol=New-Object -ComObject Outlook.Application
        $ns=$ol.Session
        foreach($acct in $ns.Accounts){
            $addr=$null; try{ $addr=$acct.SmtpAddress }catch{}
            $outlookAccounts += [PSCustomObject]@{ DisplayName=$acct.DisplayName; SmtpAddress=$addr; AccountType=$acct.AccountType }
        }
        $ol.Quit() | Out-Null
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($ns)|Out-Null
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($ol)|Out-Null
    }catch{ Write-Log -Message "Outlook COM enum failed: $_" -Level 'WARN' }
    $officeUser=$null; try{
        $idRoot='HKCU:\Software\Microsoft\Office\16.0\Common\Identity\Identities'
        if(Test-Path $idRoot){ foreach($id in Get-ChildItem $idRoot){ $p=Get-ItemProperty $id.PSPath; if($p -and $p.EmailAddress){ $officeUser=$p.EmailAddress; break } } }
    }catch{ Write-Log -Message "Office Identity read fail: $_" -Level 'WARN' }
    # Read default PDF viewer from the UserChoiceLatest key if present; fall back to UserChoice
    $pdfDefault = $null
    try {
        $kPdfLatest = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoiceLatest\ProgId'
        if (Test-Path $kPdfLatest) {
            $pdfDefault = (Get-ItemProperty $kPdfLatest).ProgId
        } else {
            $kPdf = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice'
            if (Test-Path $kPdf) {
                $pdfDefault = (Get-ItemProperty $kPdf).ProgId
            }
        }
    } catch {}

    # Read default browser (HTTP handler) from UserChoiceLatest if available; try the legacy key otherwise
    $browserDefault = $null
    try {
        $kHttpLatest = 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoiceLatest\ProgId'
        if (Test-Path $kHttpLatest) {
            $browserDefault = (Get-ItemProperty $kHttpLatest).ProgId
        } else {
            $kHttp = 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice'
            if (Test-Path $kHttp) {
                $browserDefault = (Get-ItemProperty $kHttp).ProgId
            } else {
                # fallback to Explorer FileExts http associations
                $kHttpExplorerLatest = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\http\UserChoiceLatest\ProgId'
                if (Test-Path $kHttpExplorerLatest) {
                    $browserDefault = (Get-ItemProperty $kHttpExplorerLatest).ProgId
                } else {
                    $kHttpExplorer = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\http\UserChoice'
                    if (Test-Path $kHttpExplorer) {
                        $browserDefault = (Get-ItemProperty $kHttpExplorer).ProgId
                    }
                }
            }
        }
    } catch {}
    [PSCustomObject]@{
        Username=$env:USERNAME; MappedDrives=$mapped; OutlookAccounts=$outlookAccounts; OfficeSignedInUser=$officeUser
        DefaultPdfProgId=$pdfDefault; DefaultBrowserProgId=$browserDefault
    }
}

# -------------- Chrome Password Export (guided) --------------


function Guide-ChromePasswordExport {
    if (-not $SwapInfoRoot) {
        # Try using current UI dest box if available
        try {
            if ($tbDest -and $tbDest.Text) {
                $null = Ensure-Repository -BasePath $tbDest.Text -OpenFolder:$false
            }
        } catch {}
        if (-not $SwapInfoRoot) {
            Write-Log -Message "SwapInfoRoot not set before Chrome export; aborting" -Level 'ERROR'
            return $false
        }
    }

    try{
        $paths = @()
        if ($env:ProgramFiles)        { $paths += (Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe') }
        if (${env:ProgramFiles(x86)}) { $paths += (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe') }
        if ($env:LOCALAPPDATA)        { $paths += (Join-Path $env:LOCALAPPDATA 'Google\Chrome\Application\chrome.exe') }
        try {
            $appPath = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe' -ErrorAction SilentlyContinue).'(default)'
            if ($appPath) { $paths = ,$appPath + $paths }
        } catch {}
        $found = $paths | Where-Object { Test-Path $_ } | Select-Object -First 1
        if(-not $found){ Write-Log -Message ("Chrome not found. Searched: {0}" -f ($paths -join '; ')) -Level 'WARN'; return $false }
        $target='chrome://settings/passwords'
        Start-Process -FilePath $found -ArgumentList $target
        Write-Log -Message "Opened Chrome password manager via: $found"
        [System.Windows.Forms.MessageBox]::Show(
"Chrome export steps:

1) In Chrome, Select 3 dots in top right > Passwords and Autofill >  Google Password Manager
2) Settings on the Left.
3) Select Download File next to Export Passwords.
4) Authenticate with Windows.
5) Save as: $SwapInfoRoot\$ChromeCsvName

Click OK here after saving.", "Chrome Export", 'OK','Information') | Out-Null
        $dest=Join-Path $SwapInfoRoot $ChromeCsvName
        if(Test-Path $dest){ Write-Log -Message "Chrome CSV present: $dest"; return $true } else { Write-Log -Message "Chrome CSV not found at $dest" -Level 'WARN'; return $false }
    }catch{ Write-Log -Message ("Chrome export guidance error: {0}" -f $_) -Level 'ERROR'; return $false }
}



# -------------- Wallpaper & Signatures ----------
function Copy-Wallpaper {
    try{
        $src=Join-Path $env:APPDATA 'Microsoft\Windows\Themes\TranscodedWallpaper'
        if(Test-Path $src){ $dst=Join-Path $SwapInfoRoot $WallpaperName; Copy-Safe -Source $src -Dest $dst } else { Write-Log -Message "No TranscodedWallpaper found." -Level 'WARN' }
    }catch{ Write-Log -Message "Wallpaper copy failed: $_" -Level 'ERROR' }
}
function Copy-OutlookSignatures {
    try{
        $src=Join-Path $env:APPDATA 'Microsoft\Signatures'; $dst=Join-Path $SwapInfoRoot 'Signatures'
        if(Test-Path $src){ New-Item -ItemType Directory -Path $dst -Force|Out-Null; Copy-Item (Join-Path $src '*') $dst -Recurse -Force; Write-Log -Message "Signatures copied." } else { Write-Log -Message "No signatures folder." -Level 'WARN' }
    }catch{ Write-Log -Message "Signatures copy failed: $_" -Level 'ERROR' }
}

# -------------- Deregistration Checklist --------
function Ensure-DeregList {
    if(-not (Test-Path $DeregListPath)){
        $default=@(
            @{ name = "ExampleApp Pro"; notes = "Help > Deactivate license"; completed = $false },
            @{ name = "CAD Suite";      notes = "Sign out account";         completed = $false }
        ); Save-Json -Object $default -Path $DeregListPath
    } ; Load-Json -Path $DeregListPath
}

# -------------- Manifest & Report ---------------
function Build-Manifest { param($General,$Computer,$User,$IncludeOneDrive)
    [PSCustomObject]@{
        Mode="Gather"; General=$General; Computer=$Computer; User=$User; IncludeOneDrive=[bool]$IncludeOneDrive
        CollectedBy="$env:USERDOMAIN\$env:USERNAME"; CollectedAt=(Get-Date).ToString('s')
        ChromeCsv=(Test-Path (Join-Path $SwapInfoRoot $ChromeCsvName))
        WallpaperCopied=(Test-Path (Join-Path $SwapInfoRoot $WallpaperName))
        SignaturesCopied=(Test-Path (Join-Path $SwapInfoRoot 'Signatures'))
        DeregChecklist=Ensure-DeregList
        WirelessProfilesExported=(Test-Path (Join-Path $SwapInfoRoot 'WirelessProfiles'))
        WirelessNetworks=$Computer.WirelessNetworks
        OutlookSetupAccount = $script:OutlookSetupCred
    }
}
function Write-Report { param($Manifest,$CopySummary)
    $rp=Join-Path $SwapInfoRoot $ReportName
    $L=@()
    $L += "PC Swap Technician Report - $($Manifest.General.ComputerName)"
    $L += "Generated: $(Get-Date)"
    $L += "Program Version: $ProgramVersion"
    $L += ""
    $L += "---- Summary ----"
    $L += "Include OneDrive: $($Manifest.IncludeOneDrive)"
    $L += "Chrome CSV present: $($Manifest.ChromeCsv)"
    $L += "Wallpaper copied: $($Manifest.WallpaperCopied)"
    $L += "Outlook signatures: $($Manifest.SignaturesCopied)"
    $L += ""
    $L += "---- Network ----"
    foreach($n in $Manifest.Computer.NetworkAdapters){ $L += "Adapter: $($n.InterfaceAlias) IP: $($n.IPv4Address)/$($n.SubnetMask) GW: $($n.DefaultGateway) DNS: $($n.DnsServers) DHCP: $($n.DhcpEnabled) MAC: $($n.MacAddress)" }
    $L += ""
    $L += "---- Printers ----"
    foreach($p in $Manifest.Computer.Printers){ $L += "$($p.Name) | Driver: $($p.DriverName) | Port: $($p.PortName)" }
    $L += ""
    $L += "---- Installed Programs (top 50 by name) ----"
    foreach($app in ($Manifest.Computer.InstalledPrograms | Sort-Object Name | Select-Object -First 50)){ $L += "$($app.Name) | Version: $($app.Version) | Installed: $($app.InstallDate) | Dir: $($app.InstallDir)" }
    $L += ""
    # Wireless networks
    if ($Manifest.Computer.WirelessNetworks -and $Manifest.Computer.WirelessNetworks.Count -gt 0) {
        $L += "---- Wireless Networks ----"
        foreach($w in $Manifest.Computer.WirelessNetworks){ $L += $w }
        $L += ""
    }
    $L += "---- User ----"
    $L += "Username: $($Manifest.User.Username)"
    $L += "Office signed-in user: $($Manifest.User.OfficeSignedInUser)"
    $L += "Default PDF ProgId: $($Manifest.User.DefaultPdfProgId)"
    $L += "Default Browser ProgId: $($Manifest.User.DefaultBrowserProgId)"
    $L += "Mapped Drives:"
    foreach($d in $Manifest.User.MappedDrives){ $L += "$($d.DeviceID) -> $($d.ProviderName)  ($($d.VolumeName))" }
    $L += "Outlook Accounts:"
    foreach($a in $Manifest.User.OutlookAccounts){ $L += "$($a.DisplayName) <$($a.SmtpAddress)> (Type: $($a.AccountType))" }
    $L += ""
    $L += "---- Deregistration Checklist ----"
    foreach($i in $Manifest.DeregChecklist){ $L += "[{0}] {1}  ({2})" -f ($(if($i.completed){'X'}else{' '})), $i.name, $i.notes }
    if($CopySummary){ $L += ""; $L += "---- Copy Summary ----"; $L += $CopySummary }

    # Outlook setup credentials (do not display password in clear; only show email).
    if ($Manifest.PSObject.Properties['OutlookSetupAccount']) {
        $cred = $Manifest.OutlookSetupAccount
        if ($cred -and $cred.Email) {
            $L += ""
            $L += "---- Outlook Account to Add ----"
            $L += "Email: $($cred.Email) (Password captured; not displayed)"
        }
    }
    Set-Content -Path $rp -Value ($L -join [Environment]::NewLine) -Encoding UTF8
    Write-Log -Message "Technician report written: $rp"
    $rp
}

# -------------- Copy profile (Gather) -------------------
function Copy-UserProfile {
    param([string]$BaseDestinationPath,[bool]$IncludeOneDrive)
    $hostName=$env:COMPUTERNAME; $dateStr=(Get-Date).ToString('dd-MM-yyyy')
    if([string]::IsNullOrWhiteSpace($BaseDestinationPath)){ return "Destination path empty." }
    $destRoot=$BaseDestinationPath; $dest=Join-Path $destRoot ("{0}_{1}" -f $hostName,$dateStr)
    try{ if(-not (Test-Path $destRoot)){ New-Item -ItemType Directory -Path $destRoot -Force|Out-Null }; New-Item -ItemType Directory -Path $dest -Force|Out-Null }catch{ Write-Log -Message "Create dest dirs failed: $_" -Level 'ERROR'; return "Failed to create $dest : $_" }
    $source=[Environment]::GetFolderPath("UserProfile")
    $xd=@("AppData\Local\Temp","AppData\Local\Packages","AppData\Local\Microsoft","AppData\Local\CrashDumps"); if(-not $IncludeOneDrive){ $xd += "OneDrive" }
    $xdArgs=@(); foreach($d in $xd){ $xdArgs += @("/XD",(Join-Path $source $d)) }
    $isUnc=$dest.StartsWith("\\"); $copyFlags=@("/COPY:DAT","/DCOPY:DAT"); if(-not $isUnc){ $copyFlags += "/SEC" }
    $args=@($source,$dest,"/E","/R:1","/W:1","/XJ") + $copyFlags + $xdArgs
    Write-Log -Message "Robocopy (gather) -> $dest Flags=$($copyFlags -join ' ')"
    $proc=Start-Process -FilePath robocopy.exe -ArgumentList $args -Wait -PassThru -NoNewWindow
    $code=$proc.ExitCode; Write-Log -Message "Robocopy exit code: $code"
    "Robocopy exit code: $code (0/1=OK). Source: $source Dest: $dest Flags: $($copyFlags -join ' ')"
}

# -------------- Restore helpers ----------------
function Prompt-NewHostname { param([string]$OldHostname)
    Add-Type -AssemblyName System.Windows.Forms | Out-Null
    $f=New-Object System.Windows.Forms.Form; $f.Text="New Hostname"; $f.Width=400; $f.Height=170
    $l=New-Object System.Windows.Forms.Label; $l.Text="Old hostname '$OldHostname' detected. Enter a NEW hostname:"; $l.AutoSize=$true; $l.Top=20; $l.Left=12
    $tb=New-Object System.Windows.Forms.TextBox; $tb.Top=50; $tb.Left=12; $tb.Width=360
    $ok=New-Object System.Windows.Forms.Button; $ok.Text="OK"; $ok.Top=85; $ok.Left=210; $ok.DialogResult='OK'
    $cancel=New-Object System.Windows.Forms.Button; $cancel.Text="Cancel"; $cancel.Top=85; $cancel.Left=290; $cancel.DialogResult='Cancel'
    $f.Controls.AddRange(@($l,$tb,$ok,$cancel)); $f.AcceptButton=$ok; $f.CancelButton=$cancel
    if($f.ShowDialog() -eq 'OK'){ $tb.Text } else { $null }
}
function Restore-Network { param($Manifest)
    try{
        $adapters=$Manifest.Computer.NetworkAdapters; if(-not $adapters){ Write-Log -Message "No adapters in manifest; skipping network restore." -Level 'WARN'; return }
        $target=$adapters | ? { -not $_.DhcpEnabled } | Select-Object -First 1
        if(-not $target){ Write-Log -Message "DHCP in manifest; leaving as-is."; return }
        $live=Get-NetAdapter | ? { $_.Status -eq 'Up' }
        $match=$null; if($target.MacAddress){ $match=$live | ? { $_.MacAddress -eq $target.MacAddress } }
        if(-not $match){ $match=$live | Select-Object -First 1 }
        if(-not $match){ Write-Log -Message "No active adapter to configure." -Level 'ERROR'; return }
        $alias=$match.Name; Write-Log -Message "Configuring static IP on: $alias"
        Try{ Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue }Catch{}
        Try{ Get-DnsClientServerAddress -InterfaceAlias $alias -AddressFamily IPv4 | Set-DnsClientServerAddress -ServerAddresses @() -ErrorAction SilentlyContinue }Catch{}
        New-NetIPAddress -InterfaceAlias $alias -IPAddress $target.IPv4Address -PrefixLength $target.SubnetMask -DefaultGateway $target.DefaultGateway -ErrorAction Stop | Out-Null
        if($target.DnsServers){ $dns=$target.DnsServers -split ','; Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses $dns -ErrorAction Stop }
        Write-Log -Message "Static IP configured."
    }catch{ Write-Log -Message "Network restore failed: $_" -Level 'ERROR' }
}
function Restore-WallpaperAndSignatures {
    try{
        $wpSrc=Join-Path $SwapInfoRoot $WallpaperName; if(Test-Path $wpSrc){ $wpDst=Join-Path $env:APPDATA 'Microsoft\Windows\Themes\TranscodedWallpaper'; Copy-Safe -Source $wpSrc -Dest $wpDst | Out-Null }
        $sigSrc=Join-Path $SwapInfoRoot 'Signatures'; if(Test-Path $sigSrc){ $sigDst=Join-Path $env:APPDATA 'Microsoft\Signatures'; New-Item -ItemType Directory -Path $sigDst -Force|Out-Null; Copy-Item (Join-Path $sigSrc '*') $sigDst -Recurse -Force; Write-Log -Message "Signatures restored." }
    }catch{ Write-Log -Message "Restore wallpaper/signatures failed: $_" -Level 'ERROR' }
}
function Open-DefaultAppsGuidance {
    [System.Diagnostics.Process]::Start("ms-settings:defaultapps") | Out-Null
    [System.Windows.Forms.MessageBox]::Show(
"Windows blocks scripted per-user default-app changes.
Captured defaults (manifest User.*ProgId) are shown in the report.
Set PDF and Browser now for the current user.",
"Default Apps Guidance",'OK','Information') | Out-Null
}
function Apply-SystemDefaultAppsFromManifest { param($Manifest)
    try{
        $tmpXml=Join-Path $SwapInfoRoot "DefaultApps_$TodayStamp.xml"
        $xml=@"
<?xml version="1.0" encoding="UTF-8"?>
<DefaultAssociations>
  <Association Identifier=".pdf" ProgId="$($Manifest.User.DefaultPdfProgId)" ApplicationName="PDF" />
  <Association Identifier="http" ProgId="$($Manifest.User.DefaultBrowserProgId)" ApplicationName="Browser" />
  <Association Identifier="https" ProgId="$($Manifest.User.DefaultBrowserProgId)" ApplicationName="Browser" />
</DefaultAssociations>
"@
        Set-Content -Path $tmpXml -Value $xml -Encoding UTF8
        Write-Log -Message "Importing system default app associations via DISM."
        Start-Process -FilePath dism.exe -ArgumentList "/Online","/Import-DefaultAppAssociations:$tmpXml" -Wait -NoNewWindow
    }catch{ Write-Log -Message "System default app import failed: $_" -Level 'WARN' }
}

# Local user creation and user-context resume
function Prompt-LocalUserAndPassword {
    Add-Type -AssemblyName System.Windows.Forms | Out-Null
    $form=New-Object System.Windows.Forms.Form; $form.Text="Local User for Restore"; $form.Width=420; $form.Height=230; $form.StartPosition='CenterScreen'
    $l1=New-Object System.Windows.Forms.Label; $l1.Text="Create/use local user (for post-restore resume):"; $l1.SetBounds(12,15,380,20)
    $l2=New-Object System.Windows.Forms.Label; $l2.Text="Username:"; $l2.SetBounds(12,45,100,20)
    $tbUser=New-Object System.Windows.Forms.TextBox; $tbUser.SetBounds(120,42,260,24)
    $l3=New-Object System.Windows.Forms.Label; $l3.Text="Password:"; $l3.SetBounds(12,75,100,20)
    $tbPass=New-Object System.Windows.Forms.MaskedTextBox; $tbPass.PasswordChar='*'; $tbPass.SetBounds(120,72,260,24)
    $cbAdmin=New-Object System.Windows.Forms.CheckBox; $cbAdmin.Text="Make this user local admin"; $cbAdmin.SetBounds(120,102,200,24)
    $ok=New-Object System.Windows.Forms.Button; $ok.Text="OK"; $ok.SetBounds(210,140,80,30); $ok.DialogResult='OK'
    $cancel=New-Object System.Windows.Forms.Button; $cancel.Text="Cancel"; $cancel.SetBounds(300,140,80,30); $cancel.DialogResult='Cancel'
    $form.Controls.AddRange(@($l1,$l2,$tbUser,$l3,$tbPass,$cbAdmin,$ok,$cancel)); $form.AcceptButton=$ok; $form.CancelButton=$cancel
    if($form.ShowDialog() -ne 'OK'){ return $null }
    if([string]::IsNullOrWhiteSpace($tbUser.Text) -or [string]::IsNullOrWhiteSpace($tbPass.Text)){ return $null }
    [PSCustomObject]@{ UserName=$tbUser.Text.Trim(); Password=$tbPass.Text; IsAdmin=$cbAdmin.Checked }
}

# Prompt the technician for Outlook account credentials to be used during restore.
# Returns a PSCustomObject with Email and Password fields or $null if cancelled or empty.
function Prompt-OutlookAccount {
    Add-Type -AssemblyName System.Windows.Forms | Out-Null
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Outlook Account Credentials"
    $form.Width = 420
    $form.Height = 220
    $form.StartPosition = 'CenterScreen'

    $lblInfo = New-Object System.Windows.Forms.Label
    $lblInfo.Text = "Enter the email address and password for the Outlook account that\n" +
                    "should be added on the new machine. Leave blank and click Cancel to skip."
    $lblInfo.AutoSize = $true
    $lblInfo.SetBounds(12,10,380,40)

    $lblEmail = New-Object System.Windows.Forms.Label
    $lblEmail.Text = "Email:"
    $lblEmail.SetBounds(12,60,100,20)
    $tbEmail = New-Object System.Windows.Forms.TextBox
    $tbEmail.SetBounds(120,57,260,24)

    $lblPass = New-Object System.Windows.Forms.Label
    $lblPass.Text = "Password:"
    $lblPass.SetBounds(12,90,100,20)
    $tbPass = New-Object System.Windows.Forms.MaskedTextBox
    $tbPass.PasswordChar = '*'
    $tbPass.SetBounds(120,87,260,24)

    $btnOK = New-Object System.Windows.Forms.Button
    $btnOK.Text = "OK"
    $btnOK.SetBounds(210,130,80,30)
    $btnOK.DialogResult = 'OK'

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.SetBounds(300,130,80,30)
    $btnCancel.DialogResult = 'Cancel'

    $form.Controls.AddRange(@($lblInfo,$lblEmail,$tbEmail,$lblPass,$tbPass,$btnOK,$btnCancel))
    $form.AcceptButton = $btnOK
    $form.CancelButton = $btnCancel
    if ($form.ShowDialog() -ne 'OK') { return $null }
    if ([string]::IsNullOrWhiteSpace($tbEmail.Text) -or [string]::IsNullOrWhiteSpace($tbPass.Text)) { return $null }
    return [PSCustomObject]@{ Email = $tbEmail.Text.Trim(); Password = $tbPass.Text }
}

# Show the stored Outlook account credentials to the technician during restore.
# If credentials are present, Outlook.exe is launched and a message box displays
# the email address and password.  Does not attempt to automate the account
# addition as Outlook lacks a documented API for this.
function Show-OutlookAccountForRestore { param($Cred)
    if (-not $Cred) { return }
    try {
        # Launch Outlook if not already running
        if (-not (Get-Process -Name outlook -ErrorAction SilentlyContinue)) {
            Start-Process outlook.exe | Out-Null
        }
    } catch {
        Write-Log -Message "Failed to launch Outlook: $_" -Level 'WARN'
    }
    [System.Windows.Forms.MessageBox]::Show(
"Use the following credentials to add the Outlook account on this machine.

Email: $($Cred.Email)
Password: $($Cred.Password)

Open Outlook and go to File -> Add Account, then enter the above credentials when prompted.  After the account is added, you may delete these credentials from the manifest or change the password for security.",
"Outlook Account Setup", 'OK','Information') | Out-Null
}

function Ensure-LocalUser { param([string]$UserName,[string]$PlainPassword,[bool]$MakeAdmin=$false)
    try{
        $existing=Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
        if(-not $existing){
            $sec=ConvertTo-SecureString -String $PlainPassword -AsPlainText -Force
            New-LocalUser -Name $UserName -Password $sec -FullName $UserName -PasswordNeverExpires:$true -ErrorAction Stop | Out-Null
            Add-LocalGroupMember -Group 'Users' -Member $UserName -ErrorAction SilentlyContinue
            if($MakeAdmin){ Add-LocalGroupMember -Group 'Administrators' -Member $UserName -ErrorAction SilentlyContinue }
            Write-Log -Message "Created local user $UserName (Admin=$MakeAdmin)."
        } else {
            if($PlainPassword){ $sec=ConvertTo-SecureString -String $PlainPassword -AsPlainText -Force; Set-LocalUser -Name $UserName -Password $sec -ErrorAction SilentlyContinue }
            if($MakeAdmin){ Add-LocalGroupMember -Group 'Administrators' -Member $UserName -ErrorAction SilentlyContinue }
            Write-Log -Message "Local user $UserName exists; updated."
        }
        return $true
    }catch{ Write-Log -Message "Ensure-LocalUser failed: $_" -Level 'ERROR'; return $false }
}
function Register-UserResumeTask { param([string]$UserName,[string]$ScriptPath)
    try{
        $taskName="PCSwap-Resume-User"
        $action=New-ScheduledTaskAction -Execute "powershell.exe" -Argument ("-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -ResumeUser")
        $trigger=New-ScheduledTaskTrigger -AtLogOn -User $UserName
        $principal=New-ScheduledTaskPrincipal -UserId $UserName -RunLevel Limited -LogonType Interactive
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
        Write-Log -Message "Registered user-context resume task for $UserName."
        $true
    }catch{ Write-Log -Message "Register-UserResumeTask failed: $_" -Level 'ERROR'; $false }
}

# A wrapper around Register-UserResumeTask that supports passing a manifest path.  This
# function builds the scheduled task arguments to include -ResumeUser and, if provided,
# the -Manifest parameter.  It is used by the restore workflow so that the resume
# phase can locate the correct manifest without relying solely on state.json.
function Register-UserResumeTaskEx {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$UserName,
        [Parameter(Mandatory=$true)][string]$ScriptPath,
        [string]$ManifestPath
    )
    try {
        $taskName = 'PCSwap-Resume-User'
        # Build the argument list as an array to avoid quoting issues
        $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$ScriptPath`"", '-ResumeUser')
        if ($ManifestPath) { $argList += @('-Manifest', "`"$ManifestPath`"") }
        $args    = $argList -join ' '
        $action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $args
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $UserName
        $principal = New-ScheduledTaskPrincipal -UserId $UserName -RunLevel Limited -LogonType Interactive
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
        Write-Log -Message "Registered user-context resume task for $UserName via Register-UserResumeTaskEx."
        return $true
    } catch {
        Write-Log -Message "Register-UserResumeTaskEx failed: $_" -Level 'ERROR'
        return $false
    }
}
function Copy-ProfileToUser { param([string]$SourceFolder,[string]$TargetUserName,[bool]$IncludeOneDrive)
    if(-not (Test-Path $SourceFolder)){ Write-Log -Message "Source folder missing: $SourceFolder" -Level 'ERROR'; return "Source not found: $SourceFolder" }
    $targetProfile=Join-Path 'C:\Users' $TargetUserName
    if(-not (Test-Path $targetProfile)){ New-Item -ItemType Directory -Path $targetProfile -Force | Out-Null }
    $xd=@("AppData\Local\Temp","AppData\Local\Packages","AppData\Local\Microsoft\Windows\INetCache","AppData\Local\CrashDumps"); if(-not $IncludeOneDrive){ $xd += "OneDrive" }
    $xdArgs=@(); foreach($d in $xd){ $xdArgs += @("/XD",(Join-Path $SourceFolder $d)) }
    $isUnc=$SourceFolder.StartsWith("\\"); $copyFlags=@("/COPY:DAT","/DCOPY:DAT"); if(-not $isUnc){ $copyFlags += "/SEC" }
    $args=@($SourceFolder,$targetProfile,"/E","/R:1","/W:1","/XJ") + $copyFlags + $xdArgs
    Write-Log -Message "Restoring files: $SourceFolder -> $targetProfile Flags=$($copyFlags -join ' ')"
    $proc=Start-Process -FilePath robocopy.exe -ArgumentList $args -Wait -PassThru -NoNewWindow
    $code=$proc.ExitCode
    Write-Log -Message "Robocopy restore exit code: $code"
    return "Robocopy restore exit code: $code (0/1=OK)."
}

# ------------------- GUI -----------------------
Add-Type -AssemblyName System.Windows.Forms | Out-Null
Add-Type -AssemblyName System.Drawing | Out-Null

$form = New-Object System.Windows.Forms.Form
$form.Text = "PC Swap Tool (v$ProgramVersion)"
$form.Width = 900; $form.Height = 700; $form.StartPosition = 'CenterScreen'

# Logo (optional)
if ($LogoPath -and (Test-Path $LogoPath)) {
    try { $img=[System.Drawing.Image]::FromFile($LogoPath); $pb=New-Object System.Windows.Forms.PictureBox; $pb.Image=$img; $pb.SizeMode='Zoom'; $pb.SetBounds(740,10,140,60); $form.Controls.Add($pb) } catch { Write-Log -Message "Logo load failed: $_" -Level 'WARN' }
}

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.SetBounds(10, 10, 860, 560)
$tabGather = New-Object System.Windows.Forms.TabPage; $tabGather.Text = "Gather"
$tabRestore = New-Object System.Windows.Forms.TabPage; $tabRestore.Text = "Restore"
$tabs.TabPages.AddRange(@($tabGather,$tabRestore)); $form.Controls.Add($tabs)

# -------- Gather tab controls --------
$lblDest = New-Object System.Windows.Forms.Label; $lblDest.Text = "Destination base path (network or USB). Hostname + date will be appended:"; $lblDest.SetBounds(10,10,700,20)
$tbDest = New-Object System.Windows.Forms.TextBox; $tbDest.SetBounds(10,35,650,25)
$btnBrowseDest = New-Object System.Windows.Forms.Button; $btnBrowseDest.Text = "Browse..."; $btnBrowseDest.SetBounds(670,34,80,27); $btnBrowseDest.Add_Click({ $sel=Select-FolderDialog; if($sel){ $tbDest.Text=$sel } })
$cbOneDrive = New-Object System.Windows.Forms.CheckBox; $cbOneDrive.Text = "Include OneDrive content when copying profile"; $cbOneDrive.SetBounds(10,70,350,20); $cbOneDrive.Checked = $false

# Checkbox to skip the user profile copy during gather.  Useful if the profile
# has already been copied and you simply need to re-run gather for other artifacts.
$cbSkipCopy = New-Object System.Windows.Forms.CheckBox
$cbSkipCopy.Text = "Skip profile copy"
$cbSkipCopy.SetBounds(370,70,150,20)
$cbSkipCopy.Checked = $false

# Checkbox to capture Outlook account credentials for setting up the account on restore.
$cbOutlookCred = New-Object System.Windows.Forms.CheckBox
$cbOutlookCred.Text = "Capture Outlook credentials for restore"
$cbOutlookCred.SetBounds(10,85,350,20)
$cbOutlookCred.Checked = $false
$btnChrome = New-Object System.Windows.Forms.Button; $btnChrome.Text = "Guide Chrome Password Export"; $btnChrome.SetBounds(10,100,240,30); $btnChrome.Add_Click({ Guide-ChromePasswordExport | Out-Null })
$btnWallpaper = New-Object System.Windows.Forms.Button; $btnWallpaper.Text = "Copy Current Wallpaper"; $btnWallpaper.SetBounds(260,100,180,30); $btnWallpaper.Add_Click({ Copy-Wallpaper | Out-Null })
$btnSignatures = New-Object System.Windows.Forms.Button; $btnSignatures.Text = "Copy Outlook Signatures"; $btnSignatures.SetBounds(450,100,200,30); $btnSignatures.Add_Click({ Copy-OutlookSignatures | Out-Null })
$btnDeregEdit = New-Object System.Windows.Forms.Button; $btnDeregEdit.Text = "Edit Deregistration List"; $btnDeregEdit.SetBounds(660,100,170,30); $btnDeregEdit.Add_Click({ $list=Ensure-DeregList; if(-not (Test-Path $DeregListPath)){ Save-Json -Object $list -Path $DeregListPath }; Start-Process notepad.exe $DeregListPath })
$btnStartGather = New-Object System.Windows.Forms.Button; $btnStartGather.Text = "Start Gather"; $btnStartGather.SetBounds(10,140,150,32)
$lblInfo = New-Object System.Windows.Forms.Label; $lblInfo.Text = "All collected files + manifest/report/logs are written to: $SwapInfoRoot"; $lblInfo.SetBounds(10,175,820,20)
$lvGather = New-Object System.Windows.Forms.TextBox; $lvGather.Multiline = $true; $lvGather.ReadOnly = $true; $lvGather.ScrollBars = 'Vertical'; $lvGather.SetBounds(10,205,820,300)
Add-LogSubscriber { param($line) $lvGather.AppendText($line + [Environment]::NewLine) }
$tabGather.Controls.AddRange(@(
    $lblDest,
    $tbDest,
    $btnBrowseDest,
    $cbOneDrive,
    $cbSkipCopy,
    $cbOutlookCred,
    $btnChrome,
    $btnWallpaper,
    $btnSignatures,
    $btnDeregEdit,
    $btnStartGather,
    $lblInfo,
    $lvGather
))

# Gather click
$btnStartGather.Add_Click({
    # Ensure repository exists BEFORE any action
    $destBase = $tbDest.Text
    if([string]::IsNullOrWhiteSpace($destBase)){
        $destBase = Select-FolderDialog
        if(-not $destBase){ Write-Log -Message "No destination chosen; aborting gather." -Level 'WARN'; return }
        $tbDest.Text = $destBase
    }
    $repo = Ensure-Repository -BasePath $destBase -OpenFolder:$false
    if (-not $repo) { return }

    Ensure-AdminOrWarn
    Write-Log -Message "=== GATHER START ==="

    # 1) Select & validate destination base path first
    $destBase = $tbDest.Text
    if ([string]::IsNullOrWhiteSpace($destBase)) {
        $destBase = Select-FolderDialog
        if (-not $destBase) { Write-Log -Message "No destination selected; aborting gather." -Level 'WARN'; return } else { $tbDest.Text = $destBase }
    }
    if (-not (Test-Path $destBase)) {
        [System.Windows.Forms.MessageBox]::Show("Path not found: $destBase","Path Error",'OK','Error') | Out-Null
        return
    }

    # 2) Construct dated repository path: <dest>\<HOST>_<DD-MM-YYYY>\PC_SWAP_INFO
    $dateStr = (Get-Date -Format 'dd-MM-yyyy')
    $repoBase = Join-Path $destBase ("{0}_{1}" -f $env:COMPUTERNAME, $dateStr)
    $repoRoot = Join-Path $repoBase 'PC_SWAP_INFO'
    # Use the correct parameter name (-RepoRoot) to set the repository root once the technician has selected a destination
    Set-SwapInfoRoot -RepoRoot $repoRoot

    # 3) Collect info now that $SwapInfoRoot exists
    $gen = Get-GeneralInfo
    $cmp = Get-ComputerInfoPack
    $usr = Get-UserInfoPack

    # 4) Run helpers that write into $SwapInfoRoot
    if (Get-Command Copy-Wallpaper -ErrorAction SilentlyContinue)          { $null = Copy-Wallpaper }
    if (Get-Command Copy-OutlookSignatures -ErrorAction SilentlyContinue)  { $null = Copy-OutlookSignatures }
    if (Get-Command Save-DesktopScreenshots -ErrorAction SilentlyContinue) { $null = Save-DesktopScreenshots }
    # Export wireless profiles to repository (WLAN profiles)
    if (Get-Command Export-WlanProfiles -ErrorAction SilentlyContinue) { $null = Export-WlanProfiles }

    # 5) Guide Chrome export (repo exists now)
    if (Get-Command Guide-ChromePasswordExport -ErrorAction SilentlyContinue) { $null = Guide-ChromePasswordExport }

    # 5.5) If capturing Outlook credentials, prompt now (before manifest build) and store in global
    if ($cbOutlookCred.Checked) {
        try {
            $script:OutlookSetupCred = Prompt-OutlookAccount
            if (-not $script:OutlookSetupCred) {
                Write-Log -Message "Outlook credential capture cancelled or empty." -Level 'WARN'
            } else {
                Write-Log -Message "Outlook credentials captured for restore."
            }
        } catch {
            Write-Log -Message "Prompt-OutlookAccount failed: $_" -Level 'ERROR'
        }
    } else {
        $script:OutlookSetupCred = $null
    }

    # 6) Manifest + profile copy (respect skip-copy checkbox)
    $manifest = Build-Manifest -General $gen -Computer $cmp -User $usr -IncludeOneDrive:$cbOneDrive.Checked
    $manPath  = Join-Path $SwapInfoRoot $ManifestName
    Save-Json -Object $manifest -Path $manPath -Depth 8
    Write-Log -Message "Manifest written: $manPath"

    $copySummary = ""
    if ($cbSkipCopy.Checked) {
        $copySummary = "Profile copy skipped as per technician selection."
        Write-Log -Message "Skip copy selected; not copying profile."
    } else {
        $copySummary = Copy-UserProfile -BaseDestinationPath $destBase -IncludeOneDrive:$cbOneDrive.Checked
    }

    # 7) Report + open repo
    $rp = Write-Report -Manifest $manifest -CopySummary $copySummary
    Start-Process explorer.exe $repoRoot | Out-Null
    [System.Windows.Forms.MessageBox]::Show(("Gather complete.`n`nReport: {0}`nRepository: {1}`n`nTip: In Chrome, save to this folder." -f $rp, $repoRoot), "Gather Done", 'OK','Information') | Out-Null

    Write-Log -Message "=== GATHER END ==="
})

# -------- Restore tab controls --------
$lblMan = New-Object System.Windows.Forms.Label; $lblMan.Text = "Select a manifest.json from the old machine (PC_SWAP_INFO folder):"; $lblMan.SetBounds(10,10,600,20)
$tbMan = New-Object System.Windows.Forms.TextBox; $tbMan.SetBounds(10,35,650,25)
$btnBrowseMan = New-Object System.Windows.Forms.Button; $btnBrowseMan.Text = "Browse..."; $btnBrowseMan.SetBounds(670,34,80,27); $btnBrowseMan.Add_Click({ $sel = Select-FileDialog -Filter "Manifest (manifest.json)|manifest.json|JSON (*.json)|*.json" -Title "Select manifest.json"; if($sel){ $tbMan.Text = $sel } })
$lblDom = New-Object System.Windows.Forms.Label; $lblDom.Text = "Optional: Join Domain (leave blank to skip). Domain name:"; $lblDom.SetBounds(10,70,400,20)
$tbDomain = New-Object System.Windows.Forms.TextBox; $tbDomain.SetBounds(10,95,300,25)
$lblOU = New-Object System.Windows.Forms.Label; $lblOU.Text = "Optional OU (distinguished name):"; $lblOU.SetBounds(320,70,250,20)
$tbOU = New-Object System.Windows.Forms.TextBox; $tbOU.SetBounds(320,95,300,25)
$btnStartRestore = New-Object System.Windows.Forms.Button; $btnStartRestore.Text = "Start Restore"; $btnStartRestore.SetBounds(10,130,150,32)
$btnDefaults = New-Object System.Windows.Forms.Button; $btnDefaults.Text = "Open Default Apps Guidance"; $btnDefaults.SetBounds(170,130,220,32); $btnDefaults.Add_Click({ Open-DefaultAppsGuidance })
$btnApplySysDefaults = New-Object System.Windows.Forms.Button; $btnApplySysDefaults.Text = "Apply System Default Apps (DISM)"; $btnApplySysDefaults.SetBounds(400,130,240,32); $btnApplySysDefaults.Add_Click({ $m=$null; if(Test-Path $tbMan.Text){ $m=Load-Json -Path $tbMan.Text }; if($m){ Apply-SystemDefaultAppsFromManifest -Manifest $m } })
# Profile source root picker
$lblSrc = New-Object System.Windows.Forms.Label; $lblSrc.Text = "Profile source ROOT (contains OLDHOST_DD-MM-YYYY folder):"; $lblSrc.SetBounds(10,170,480,20)
$tbSrcRoot = New-Object System.Windows.Forms.TextBox; $tbSrcRoot.SetBounds(10,195,650,25)
$btnBrowseSrc = New-Object System.Windows.Forms.Button; $btnBrowseSrc.Text = "Browse..."; $btnBrowseSrc.SetBounds(670,194,80,27); $btnBrowseSrc.Add_Click({ $sel=Select-FolderDialog; if($sel){ $tbSrcRoot.Text=$sel } })
$lvRestore = New-Object System.Windows.Forms.TextBox; $lvRestore.Multiline = $true; $lvRestore.ReadOnly = $true; $lvRestore.ScrollBars = 'Vertical'; $lvRestore.SetBounds(10,230,820,275)
Add-LogSubscriber { param($line) $lvRestore.AppendText($line + [Environment]::NewLine) }
$tabRestore.Controls.AddRange(@($lblMan,$tbMan,$btnBrowseMan,$lblDom,$tbDomain,$lblOU,$tbOU,$btnStartRestore,$btnDefaults,$btnApplySysDefaults,$lblSrc,$tbSrcRoot,$btnBrowseSrc,$lvRestore))

# Restore click
$btnStartRestore.Add_Click({
    Ensure-AdminOrWarn
    Write-Log -Message "=== RESTORE START ==="
    if (-not (Test-Path $tbMan.Text)) { [System.Windows.Forms.MessageBox]::Show("Please select a valid manifest.json.","Missing Manifest",'OK','Warning') | Out-Null; return }
    $manifest = Load-Json -Path $tbMan.Text
    if (-not $manifest) { [System.Windows.Forms.MessageBox]::Show("Manifest could not be parsed.","Manifest Error",'OK','Error') | Out-Null; return }

    # Set repository root based on the selected manifest so that state.json and other repo
    # artifacts are written/read from the correct location during restore.
    try {
        $manDir = Split-Path -Parent $tbMan.Text
        if ($manDir) { Set-SwapInfoRoot -RepoRoot $manDir }
    } catch {}

    $newName = Prompt-NewHostname -OldHostname $manifest.Computer.Hostname
    if ([string]::IsNullOrWhiteSpace($newName)) { Write-Log -Message "Hostname change cancelled by technician." -Level 'WARN' } 
    else {
        if ($newName -ieq $manifest.Computer.Hostname) {
            [System.Windows.Forms.MessageBox]::Show("New hostname must DIFFER from old hostname.","Invalid Name",'OK','Error') | Out-Null; return
        }
        try { Rename-Computer -NewName $newName -ErrorAction Stop; Write-Log -Message "Hostname set to $newName (pending reboot)." } catch { Write-Log -Message "Failed to rename computer: $_" -Level 'ERROR' }
    }

    $domain = $tbDomain.Text.Trim()
    $ou     = $tbOU.Text.Trim()
    $needReboot = $false
    $createdLocalUser = $false
    $targetLocalUser  = $null

    if ($domain) {
        try {
            $cred = $Host.UI.PromptForCredential("Domain Join","Enter credentials permitted to join $domain","$env:USERDOMAIN\$env:USERNAME",$domain)
            if ($ou) { Add-Computer -DomainName $domain -OUPath $ou -Credential $cred -ErrorAction Stop }
            else     { Add-Computer -DomainName $domain -Credential $cred -ErrorAction Stop }
            Write-Log -Message "Domain join scheduled."
            $needReboot = $true
        } catch { Write-Log -Message "Domain join failed: $_" -Level 'ERROR' }
    } else {
        $up = Prompt-LocalUserAndPassword
        if ($up -eq $null) { [System.Windows.Forms.MessageBox]::Show("Local user creation cancelled.","Restore","OK","Warning") | Out-Null; return }
        if (Ensure-LocalUser -UserName $up.UserName -PlainPassword $up.Password -MakeAdmin:$up.IsAdmin) {
            $createdLocalUser = $true; $targetLocalUser  = $up.UserName
        }
    }

    # Resolve profile source
    $profileSource = $null
    if ($tbSrcRoot.Text -and (Test-Path $tbSrcRoot.Text)) {
        $oldHost = $manifest.Computer.Hostname
        $candidates = Get-ChildItem -Path $tbSrcRoot.Text -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "$oldHost*" } | Sort-Object Name -Descending
        if ($candidates -and $candidates.Count -gt 0) { $profileSource = $candidates[0].FullName }
        else { $profileSource = $tbSrcRoot.Text }
        Write-Log -Message "Profile source resolved to: $profileSource"
    } else {
        Write-Log -Message "No profile source root provided; profile restore will require manual copy later." -Level 'WARN'
    }

    # Save state and register resumes
    $state = @{ NextPhase = "PostJoin"; ManifestPath = $tbMan.Text; ProfileSource = $profileSource; IncludeOneDrive = [bool]$manifest.IncludeOneDrive; TargetLocalUser = $targetLocalUser }
    Save-Json -Object $state -Path $StatePath
    # Include manifest path when scheduling resume tasks so the resume phases can load
    # the correct manifest without relying on state.json alone.
    New-RunOnceResume -ScriptPath $PSCommandPath -ManifestPath $tbMan.Text
    if ($createdLocalUser) { Register-UserResumeTaskEx -UserName $targetLocalUser -ScriptPath $PSCommandPath -ManifestPath $tbMan.Text | Out-Null }

    if ($domain -or $newName) {
        [System.Windows.Forms.MessageBox]::Show("System needs to reboot to continue restore. After reboot, log into the intended user to complete file restore.","Reboot Required",'OK','Information') | Out-Null
        Write-Log -Message "Rebooting to continue restore."
        Restart-Computer -Force
        return
    }

    # If no reboot needed: perform system-context steps now; file copy will occur at user logon if targetLocalUser defined.
    Restore-Network -Manifest $manifest
    # Restore wireless profiles if exported
    try {
        $wifiFolder = Join-Path $SwapInfoRoot 'WirelessProfiles'
        if (Test-Path $wifiFolder) {
            Import-WlanProfiles -ProfileFolder $wifiFolder | Out-Null
        }
    } catch { Write-Log -Message "Wireless profile import error: $($_)" -Level 'WARN' }
    Restore-WallpaperAndSignatures
    Open-DefaultAppsGuidance
    # Do not show Outlook credentials during system-context restore; this will be handled in user context
    Write-Log -Message "=== RESTORE END ==="
})

# ----------------- Resume Paths ------------------
if ($Resume) {
    Write-Log -Message "=== RESUME START ==="
    # Attempt to load the saved state from state.json.  The state stores the manifest path
    # but if a manifest was supplied on the command line we will honor that instead.
    $state = Load-Json -Path $StatePath
    $manifestPath = $null
    if ($ManifestOverride) {
        $manifestPath = $ManifestOverride
    } elseif ($state) {
        $manifestPath = $state.ManifestPath
    }
    if ($manifestPath) {
        # Set the repository root based on the manifest path so that subsequent operations
        # (like reading state.json or writing logs) go to the correct location.
        try {
            $repoDir = Split-Path -Parent $manifestPath
            if ($repoDir) { Set-SwapInfoRoot -RepoRoot $repoDir }
        } catch {}
        $manifest = Load-Json -Path $manifestPath
        if ($manifest) {
            Restore-Network -Manifest $manifest
            # Import Wi‑Fi profiles if folder exists
            try {
                $wifiFolder = Join-Path $SwapInfoRoot 'WirelessProfiles'
                if (Test-Path $wifiFolder) {
                    Import-WlanProfiles -ProfileFolder $wifiFolder | Out-Null
                }
            } catch { Write-Log -Message "Wireless profile import error (resume): $($_)" -Level 'WARN' }
            Restore-WallpaperAndSignatures
            Open-DefaultAppsGuidance
            # Do not display Outlook credentials in system context; this will be handled in user resume
            Write-Log -Message "Post-join steps executed."
        } else {
            Write-Log -Message "Manifest missing on resume (path: $manifestPath)." -Level 'ERROR'
        }
    } else {
        Write-Log -Message "No manifest path found on resume." -Level 'ERROR'
    }
    Write-Log -Message "=== RESUME END ==="
}

if ($ResumeUser) {
    Write-Log -Message "=== USER RESUME START ==="
    $state = Load-Json -Path $StatePath
    # Determine manifest path: honor -Manifest argument if supplied; otherwise use state.json
    $manifestPath = $null
    if ($ManifestOverride) {
        $manifestPath = $ManifestOverride
    } elseif ($state) {
        $manifestPath = $state.ManifestPath
    }
    # Set repository root based on manifest path so that $SwapInfoRoot and related paths are valid
    if ($manifestPath) {
        try {
            $repoDir = Split-Path -Parent $manifestPath
            if ($repoDir) { Set-SwapInfoRoot -RepoRoot $repoDir }
        } catch {}
    }
    if ($state) {
        $targetUser = $env:USERNAME
        $src = $state.ProfileSource
        $incl = [bool]$state.IncludeOneDrive
        if ($src) {
            $summary = Copy-ProfileToUser -SourceFolder $src -TargetUserName $targetUser -IncludeOneDrive:$incl
            Write-Log -Message $summary
            Restore-WallpaperAndSignatures
            Open-DefaultAppsGuidance
            # Load the manifest for Outlook credentials (prefer manifest override)
            $manifest = $null
            if ($manifestPath) {
                try { $manifest = Load-Json -Path $manifestPath } catch {}
            }
            if ($manifest -and $manifest.PSObject.Properties['OutlookSetupAccount']) {
                try {
                    Show-OutlookAccountForRestore -Cred $manifest.OutlookSetupAccount
                } catch {
                    Write-Log -Message "Failed to display Outlook credentials (user resume): $_" -Level 'ERROR'
                }
            }
        } else {
            Write-Log -Message "No profile source defined; skipping file restore." -Level 'WARN'
        }
    } else {
        Write-Log -Message "No state.json for user resume." -Level 'ERROR'
    }
    Write-Log -Message "=== USER RESUME END ==="
    exit 0
}

# ----------------- Show Form --------------------
$form.Add_Shown({ $form.Activate() })
[void]$form.ShowDialog()