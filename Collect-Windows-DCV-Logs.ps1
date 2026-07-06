<#
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

.SYNOPSIS
    Collects Amazon DCV logs and system information into a bundle for troubleshooting.
.DESCRIPTION
    This script gathers various logs and configuration information related to Amazon DCV,
    including EC2 instance metadata, installed applications, group policies, and DCV configurations.
.NOTES
    Requires: PowerShell 5.1 or later
    Author: AWS
#>

# NOTE: This script intentionally does NOT use [CmdletBinding()]/a typed param()
# block so that GNU double-dash style flags (e.g. --without-upload) land in the
# automatic $args variable and can be parsed manually below. See the parameter
# parsing section near the bottom of the file (just before Main is invoked).

# Add required assemblies
Add-Type -AssemblyName System.Web

# Constants
$script:DCVPath = 'C:\Program Files\NICE\DCV\Server\bin\dcv.exe'
$script:MetadataBaseUrl = 'http://169.254.169.254/latest'
$script:LogBundleName = 'DCVLogBundle'
$script:CollectionScriptVersion = '2026.08'
$script:Hostname = $env:COMPUTERNAME
$script:CompressedFileName = "dcv_logs_collection_$($script:Hostname).zip"
# AI log analysis: upload the (unencrypted) bundle to the NI SP upload service,
# then request an analysis from Deep NI SP, which returns a private report link.
$script:UploadServiceBase = 'https://ni-sp.com:9443'
$script:DeepAiBase = 'https://deep.ni-sp.com'
$script:ProductKey = 'dcv-windows'

# Global variables
$script:EncryptPassword = ""
$script:BundlePath = ""
$script:HostnameBundlePath = ""
$script:CollectGpoResults = $false # Default to not collecting GPO

# Command-line option flags (populated by the parameter parsing section below)
$script:SkipUpload      = $false   # --without-upload
$script:SkipEncryption  = $false   # --without-encryption
$script:SkipCompression = $false   # --without-compression
$script:NonInteractive  = $false   # --collect-logs (run with no interactive menu)
$script:ProxyUrl        = ""        # --proxy
$script:Message         = ""        # --message (deprecated; used as the problem text)
$script:SupportName     = ""        # --name  (for the AI analysis request)
$script:SupportEmail    = ""        # --email (for the AI analysis request)
$script:SupportProblem  = ""        # --problem (short problem description)

function Write-ColoredOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    
    switch ($Color) {
        "Green" { Write-Host $Message -ForegroundColor Green }
        "Yellow" { Write-Host $Message -ForegroundColor Yellow }
        "Red" { Write-Host $Message -ForegroundColor Red }
        "Blue" { Write-Host $Message -ForegroundColor Blue }
        default { Write-Host $Message }
    }
}

function Show-Help {
    Write-Host ""
    Write-ColoredOutput "NI SP DCV Log Collection Tool - Help" "Green"
    Write-Host "#################################################"
    Write-Host "Collects Amazon/NICE DCV logs and system information into a bundle for troubleshooting."
    Write-Host ""
    Write-ColoredOutput "USAGE:" "Yellow"
    Write-Host "  .\Collect-Windows-DCV-Logs.ps1 [options]"
    Write-Host ""
    Write-ColoredOutput "OPTIONS:" "Yellow"
    Write-Host "  --without-upload        Skip upload; keep the file locally for manual upload."
    Write-Host "  --without-encryption    Create the compressed file without encryption"
    Write-Host "                          (on Windows this means a plain ZIP without a password)."
    Write-Host "  --collect-logs          Only collect logs (no interactive menu / prompts)."
    Write-Host "  --proxy <url>           Use a proxy for uploading"
    Write-Host "                          (e.g. http://proxy:8080, socks5://proxy:1080)."
    Write-Host "  --name <text>           Your name or company (for the AI analysis request)."
    Write-Host "  --email <addr>          Your e-mail so NI SP Support can reach you."
    Write-Host "  --problem <text>        Short description of the problem you are seeing."
    Write-Host "  --message <text>        Deprecated alias; used as the problem description."
    Write-Host "  --without-compression   Skip compression (keeps logs as a directory)."
    Write-Host "                          Also implicitly sets --without-encryption and --without-upload."
    Write-Host "  --help, -h              Show this help message and exit."
    Write-Host ""
    Write-Host "  The logs are uploaded to NI SP and sent to Deep NI SP for an automatic AI"
    Write-Host "  analysis; the script prints a private report link (ready within ~30 minutes)."
    Write-Host "  --name, --email and --problem are mandatory for a non-interactive run."
    Write-Host ""
    Write-ColoredOutput "EXAMPLES:" "Yellow"
    Write-Host "  # Interactive run (default behaviour)"
    Write-Host "  .\Collect-Windows-DCV-Logs.ps1"
    Write-Host ""
    Write-Host "  # Fully unattended collection + AI analysis"
    Write-Host "  .\Collect-Windows-DCV-Logs.ps1 --collect-logs --name ""ACME"" --email jane@acme.com --problem ""black screen"""
    Write-Host ""
    Write-Host "  # Collect and keep the file locally, no upload"
    Write-Host "  .\Collect-Windows-DCV-Logs.ps1 --collect-logs --without-upload"
    Write-Host ""
    Write-Host "  # Collect raw logs as a plain directory (no zip, no encryption, no upload)"
    Write-Host "  .\Collect-Windows-DCV-Logs.ps1 --collect-logs --without-compression"
    Write-Host "#################################################"
}

# Returns a hashtable to splat onto Invoke-WebRequest / Invoke-RestMethod so the
# configured proxy (if any) is applied. Empty when no --proxy was supplied.
function Get-ProxySplat {
    $splat = @{}
    if (-not [string]::IsNullOrWhiteSpace($script:ProxyUrl)) {
        $splat['Proxy'] = $script:ProxyUrl
    }
    return $splat
}

function Show-WelcomeMessage {
    # Non-interactive mode (--collect-logs): no prompts. Name/email/problem must
    # have been supplied via flags (Get-SupportDetails aborts otherwise).
    if ($script:NonInteractive) {
        Write-ColoredOutput "NI SP DCV Log Collection Tool (non-interactive mode)" "Green"
        if (-not $script:SkipUpload) {
            Get-SupportDetails
        }
        # GPO results may be sensitive; do not collect them unattended.
        $script:CollectGpoResults = $false
        return
    }

    Write-Host "#################################################"
    Write-ColoredOutput "Welcome to NI SP DCV Log Collection Tool!" "Green"
    Write-ColoredOutput "Check all of our guides and tools: https://github.com/NISP-GmbH/Guides" "Green"
    Write-Host "#################################################"
    Write-ColoredOutput "Notes:" "Green"
    Write-ColoredOutput "- The script will not restart any service." "Green"
    Write-Host "#################################################"
    Write-ColoredOutput "Disclaimer:" "Yellow"
    Write-ColoredOutput "- This script collects system and application data for troubleshooting, including:" "Yellow"
    Write-ColoredOutput "  - System Information (systeminfo, network config, Windows version)" "Yellow"
    Write-ColoredOutput "  - Installed applications list" "Yellow"
    Write-ColoredOutput "  - Group Policy (GPO) results (if you consent)" "Yellow"
    Write-ColoredOutput "  - EC2 instance metadata (if applicable)" "Yellow"
    Write-ColoredOutput "  - NICE DCV logs and configuration" "Yellow"
    Write-ColoredOutput "  - Windows Event Logs (last 7 days)" "Yellow"
    Write-ColoredOutput "  - Windows Crash Dumps (last 7 days)" "Yellow"
    Write-ColoredOutput "- The collected data will be compressed, encrypted, and uploaded for analysis." "Yellow"
    Write-Host "#################################################"

    Write-ColoredOutput "This script will collect relevant logs to send to NISP Support Team." "Green"
    Write-Host "In the end an encrypted file will be created, then it will be securely uploaded to NISP and a notification will be sent to NISP Support Team."
    Write-Host "If you do not have internet access when executing this script, you will have an option to store the file in the end."
    Write-Host ""
    
    Write-ColoredOutput "Do you want to proceed with log collection? (Y/N):" "Green"
    do {
        $confirmation = Read-Host
    } while ($confirmation -notin @("Y", "y", "Yes", "yes", "N", "n", "No", "no"))
    
    if ($confirmation -match "^(N|n|No|no)$") {
        Write-ColoredOutput "Log collection cancelled by user." "Yellow"
        exit 0
    }
    
    Write-Host ""
    # Name, e-mail and a short problem description are mandatory for the AI
    # analysis request (not needed with --without-upload).
    if (-not $script:SkipUpload) {
        Get-SupportDetails
    }

    Write-Host ""
    Write-ColoredOutput "Collect Group Policy (GPO) Information?" "Yellow"
    Write-Host "Group Policy results contain detailed security and configuration rules for your computer and domain (e.g., password policies, software restrictions, network settings)."
    Write-Host "This information is very useful for troubleshooting but can be sensitive."
    Write-ColoredOutput "Do you want to include GPO results in the log bundle? (Y/N):" "Green"
    
    do {
        $gpoConfirmation = Read-Host
    } while ($gpoConfirmation -notin @("Y", "y", "Yes", "yes", "N", "n", "No", "no"))
    
    if ($gpoConfirmation -match "^(Y|y|Yes|yes)$") {
        $script:CollectGpoResults = $true
        Write-Host "GPO results will be collected."
    } else {
        $script:CollectGpoResults = $false
        Write-Host "Skipping GPO results collection."
    }
}

function Generate-RandomPassword {
    param([int]$Length = 32)
    
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%^&*()_=+-"
    $password = ""
    $random = New-Object System.Random
    
    for ($i = 0; $i -lt $Length; $i++) {
        $password += $chars[$random.Next(0, $chars.Length)]
    }
    
    return $password
}

function New-PasswordProtectedZip {
    param(
        [string]$SourcePath,
        [string]$DestinationPath,
        [string]$Password
    )
    
    try {
        $sevenZipPath = Get-Command "7z.exe" -ErrorAction SilentlyContinue
        
        if ($sevenZipPath) {
            Write-ColoredOutput "Using 7-Zip for password protection..." "Green"
            & $sevenZipPath.Source a -tzip -p"$Password" "$DestinationPath" "$SourcePath\*" -r
        }
        else {
            Write-ColoredOutput "Creating ZIP file (7-Zip not found for password protection)..." "Yellow"

            Add-Type -AssemblyName System.IO.Compression.FileSystem
            if (Test-Path $DestinationPath) { Remove-Item $DestinationPath -Force }
            [System.IO.Compression.ZipFile]::CreateFromDirectory($SourcePath, $DestinationPath)

            $passwordFile = [System.IO.Path]::ChangeExtension($DestinationPath, ".password.txt")
            "Password: $Password" | Set-Content -Path $passwordFile
            Write-ColoredOutput "Password saved to: $passwordFile" "Yellow"
        }
        
        return $true
    }
    catch {
        Write-Error "Failed to create password-protected ZIP: $_"
        return $false
    }
}

# Collect the mandatory contact details for the AI analysis request. Values may
# be supplied non-interactively via --name / --email / --problem; interactive
# runs are prompted. Non-interactive runs missing a value abort with an error.
function Get-SupportDetails {
    $emailRegex = '^[^@\s]+@[^@\s]+\.[^@\s]+$'

    if ([string]::IsNullOrWhiteSpace($script:SupportName)) {
        if ($script:NonInteractive) { Write-ColoredOutput "ERROR: --name is required in non-interactive mode." "Red"; exit 26 }
        do {
            Write-ColoredOutput "[REQUIRED] Your name or company:" "Yellow"
            $script:SupportName = Read-Host
        } while ([string]::IsNullOrWhiteSpace($script:SupportName))
    }

    if ([string]::IsNullOrWhiteSpace($script:SupportEmail)) {
        if ($script:NonInteractive) { Write-ColoredOutput "ERROR: --email is required in non-interactive mode." "Red"; exit 26 }
        do {
            Write-ColoredOutput "[REQUIRED] Your e-mail (so NI SP Support can reach you):" "Yellow"
            $script:SupportEmail = Read-Host
        } while ($script:SupportEmail -notmatch $emailRegex)
    }
    elseif ($script:SupportEmail -notmatch $emailRegex) {
        Write-ColoredOutput "ERROR: --email is not a valid address." "Red"; exit 26
    }

    if ([string]::IsNullOrWhiteSpace($script:SupportProblem)) {
        if ($script:NonInteractive) { Write-ColoredOutput "ERROR: --problem is required in non-interactive mode." "Red"; exit 26 }
        do {
            Write-ColoredOutput "[REQUIRED] Briefly describe the problem you are seeing:" "Yellow"
            $script:SupportProblem = Read-Host
        } while ([string]::IsNullOrWhiteSpace($script:SupportProblem))
    }

    Write-ColoredOutput "By continuing, you authorize NI SP to process the (unencrypted) log bundle to generate an AI analysis." "Green"
}

# Upload a bundle to the NI SP upload service (tus protocol) and request an AI
# log analysis from Deep NI SP. Prints the private report link on success; on
# any failure it keeps the bundle locally and prints the manual-upload hint.
function Invoke-SendToSupport {
    param(
        [string]$FilePath
    )

    $proxySplat = Get-ProxySplat
    if ($proxySplat.Count -gt 0) { Write-Host "Using proxy: $script:ProxyUrl" }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls

    try {
        $fileName    = [System.IO.Path]::GetFileName($FilePath)
        $fileBytes   = [System.IO.File]::ReadAllBytes($FilePath)
        $fileNameB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($fileName))
        $fileSizeMB  = [math]::Round($fileBytes.Length / 1MB, 2)

        Write-ColoredOutput "Uploading the logs to NI SP ($fileSizeMB MB)..." "Green"

        # 1) tus create — declare the length + filename, receive an upload Location.
        $createHeaders = @{
            'Tus-Resumable'   = '1.0.0'
            'Upload-Length'   = "$($fileBytes.Length)"
            'Upload-Metadata' = "filename $fileNameB64"
        }
        $createResp = Invoke-WebRequest -Uri "$script:UploadServiceBase/files/" -Method Post -Headers $createHeaders -TimeoutSec 60 -UseBasicParsing @proxySplat
        $location = $createResp.Headers['Location']
        if ([string]::IsNullOrWhiteSpace($location)) { throw "the upload service did not return a Location." }

        # 2) tus send bytes — single PATCH of the whole file at offset 0.
        $patchHeaders = @{
            'Tus-Resumable' = '1.0.0'
            'Upload-Offset' = '0'
        }
        Invoke-WebRequest -Uri $location -Method Patch -Headers $patchHeaders -Body $fileBytes -ContentType 'application/offset+octet-stream' -UseBasicParsing @proxySplat | Out-Null

        # 3) sign — turn the upload id into a signed, time-limited download link.
        $uploadId = ($location.TrimEnd('/') -split '/')[-1]
        $signResp = Invoke-RestMethod -Uri "$script:UploadServiceBase/sign/$uploadId" -TimeoutSec 60 -UseBasicParsing @proxySplat
        if ([string]::IsNullOrWhiteSpace($signResp.url)) { throw "no download link was returned." }
        $downloadUrl = "$script:UploadServiceBase$($signResp.url)"

        # 4) request AI analysis — Deep NI SP queues the job and returns a report link.
        Write-ColoredOutput "Requesting AI log analysis..." "Green"
        $form = @{
            product             = $script:ProductKey
            problem_description = $script:SupportProblem
            contact_name        = $script:SupportName
            contact_email       = $script:SupportEmail
            consent             = 'on'
            source_url          = $downloadUrl
        }
        $analysisResp = Invoke-RestMethod -Uri "$script:DeepAiBase/api/upload" -Method Post -Body $form -TimeoutSec 60 -UseBasicParsing @proxySplat
        if ([string]::IsNullOrWhiteSpace($analysisResp.result_url)) { throw "the analysis request was rejected." }
        $reportUrl = "$script:DeepAiBase$($analysisResp.result_url)"

        Write-Host "#########################################################################"
        Write-ColoredOutput "Your logs were sent to NI SP for AI analysis." "Green"
        Write-ColoredOutput "Your report will be ready within ~30 minutes at:" "Green"
        Write-ColoredOutput $reportUrl "Yellow"
        Write-ColoredOutput "Bookmark this private link - it is how you and NI SP Support read the result." "Green"
        Write-Host "#########################################################################"
    }
    catch {
        Write-Warning "Automatic send / analysis failed: $_"
        Write-ColoredOutput "The log bundle was kept locally at:" "Yellow"
        Write-ColoredOutput $FilePath "Green"
        Write-ColoredOutput "You can upload it manually to: $script:UploadServiceBase/" "Green"
        Write-ColoredOutput "then use the 'Ask Deep NI SP to analyze these logs' button." "Green"
    }
}

function Remove-TempFiles {
    Write-Host "Cleaning temp files..."
    
    $zipPath = Join-Path -Path $PSScriptRoot -ChildPath $script:CompressedFileName
    
    if (Test-Path $zipPath) {
        if ($script:NonInteractive) {
            # No prompts in non-interactive mode: always keep the file.
            Write-ColoredOutput "File kept at: $zipPath" "Green"
            $passwordFile = [System.IO.Path]::ChangeExtension($zipPath, ".password.txt")
            if (Test-Path $passwordFile) {
                Write-ColoredOutput "Password file kept at: $passwordFile" "Yellow"
            }
        }
        else {
            Write-ColoredOutput "Do you want to delete the $script:CompressedFileName?" "Green"
            Write-Host "If you have no internet to upload the file, you can manually send to NISP Support Team."
            Write-Host "Write Yes/Y to delete. Any other response will keep the file."

            $userAnswer = Read-Host

            if ($userAnswer -match "^(y|yes)$") {
                Remove-Item -Path $zipPath -Force
                Write-ColoredOutput "File deleted." "Green"
            }
            else {
                Write-ColoredOutput "File kept at: $zipPath" "Green"
                # Also keep password file if it exists
                $passwordFile = [System.IO.Path]::ChangeExtension($zipPath, ".password.txt")
                if (Test-Path $passwordFile) {
                    Write-ColoredOutput "Password file kept at: $passwordFile" "Yellow"
                }
            }
        }
    }
    
    # Clean up temporary bundle directory
    if (Test-Path $script:HostnameBundlePath) {
        Remove-Item -Path $script:HostnameBundlePath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Show-ByeByeMessage {
    Write-ColoredOutput "Thank you!" "Green"
}

function Get-EC2InstanceMetadata {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $token = $null
    try {
        $tokenHeaders = @{
            'X-aws-ec2-metadata-token-ttl-seconds' = '21600'
        }
        $token = Invoke-RestMethod -Headers $tokenHeaders -Method PUT -Uri "$script:MetadataBaseUrl/api/token" -TimeoutSec 5
        
        $headers = @{
            'X-aws-ec2-metadata-token' = $token
        }

        # Create hashtable of metadata endpoints to retrieve
        $metadataEndpoints = @{
            AMI = 'meta-data/ami-id'
            InstanceId = 'meta-data/instance-id'
            AvailabilityZone = 'meta-data/placement/availability-zone'
            AvailabilityZoneId = 'meta-data/placement/availability-zone-id'
            Region = 'meta-data/placement/region'
            HardwareHistory = 'meta-data/events/maintenance/history'
            PublicIP = 'meta-data/public-ipv4'
        }

        $metadata = @{}
        foreach ($endpoint in $metadataEndpoints.GetEnumerator()) {
            try {
                $value = Invoke-RestMethod -Headers $headers -Method GET -Uri "$script:MetadataBaseUrl/$($endpoint.Value)" -TimeoutSec 5
                $metadata[$endpoint.Key] = if ([string]::IsNullOrEmpty($value) -and $endpoint.Key -eq 'HardwareHistory') {
                    'No Reported Maintenance Events'
                } else {
                    $value
                }
            }
            catch {
                Write-Warning "Failed to retrieve $($endpoint.Key): $_"
                $metadata[$endpoint.Key] = $null
            }
        }

        return [PSCustomObject]$metadata
    }
    catch {
        Write-Warning "Not running on EC2 or failed to retrieve metadata"
        return $null
    }
}

function Get-InstalledApplications() {
    $keys = @(
        'Software\Microsoft\Windows\CurrentVersion\Uninstall'
        'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    $baseKeys = [System.Collections.Generic.List[Microsoft.Win32.RegistryKey]]::new()
    $ComputerName = $env:COMPUTERNAME

    $baseKeys.Add([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName, 'Registry64'))
    try {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', $ComputerName, 'Registry64')
        foreach ($name in $baseKey.GetSubKeyNames()) {
            if (-not $name.EndsWith('_Classes')) {
                Write-Debug ('Opening {0}' -f $name)

                try {
                    $baseKeys.Add($baseKey.OpenSubKey($name, $false))
                } catch {
                    $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                        $_.Exception.GetType()::new(
                            ('Unable to access sub key {0} ({1})' -f $name, $_.Exception.InnerException.Message.Trim()),
                            $_.Exception
                        ),
                        'SubkeyAccessError',
                        'InvalidOperation',
                        $name
                    )
                    Write-Error -ErrorRecord $errorRecord
                }
            }
        }
    } catch [Exception] {
        Write-Error -ErrorRecord $_
    }

    $installedApps = @()
    foreach ($baseKey in $baseKeys) {
        Write-Verbose ('Reading {0}' -f $baseKey.Name)

        if ($basekey.Name -eq 'HKEY_LOCAL_MACHINE') {
            $username = 'LocalMachine'
        } else {
            # Attempt to resolve a SID
            try {
                [System.Security.Principal.SecurityIdentifier]$sid = Split-Path $baseKey.Name -Leaf
                $username = $sid.Translate([System.Security.Principal.NTAccount]).Value
            } catch {
                $username = Split-Path $baseKey.Name -Leaf
            }
        }

        foreach ($key in $keys) {
            try {
                $uninstallKey = $baseKey.OpenSubKey($key, $false)

                if ($uninstallKey) {
                    $is64Bit = $true
                    if ($key -match 'Wow6432Node') {
                        $is64Bit = $false
                    }
                    
                    foreach ($name in $uninstallKey.GetSubKeyNames()) {
                        $packageKey = $uninstallKey.OpenSubKey($name)

                        $installDate = Get-Date
                        $dateString = $packageKey.GetValue('InstallDate')
                        if (-not $dateString -or -not [DateTime]::TryParseExact($dateString, 'yyyyMMdd', (Get-Culture), 'None', [Ref]$installDate)) {
                            $installDate = $null
                        }

                        $installedApps += [PSCustomObject]@{
                            Name            = $name
                            DisplayName     = $packageKey.GetValue('DisplayName')
                            DisplayVersion  = $packageKey.GetValue('DisplayVersion')
                            InstallDate     = $installDate
                            InstallLocation = $packageKey.GetValue('InstallLocation')
                            HelpLink        = $packageKey.GetValue('HelpLink')
                            Publisher       = $packageKey.GetValue('Publisher')
                            UninstallString = $packageKey.GetValue('UninstallString')
                            URLInfoAbout    = $packageKey.GetValue('URLInfoAbout')
                            Is64Bit         = $is64Bit
                            Hive            = $baseKey.Name
                            Path            = Join-Path -Path $key -ChildPath $name
                            Username        = $username
                            ComputerName    = $ComputerName
                        }
                    }
                }
            } catch {
                Write-Error -ErrorRecord $_
            }
        }
    }

    return $installedApps | Select-Object Name, DisplayName, DisplayVersion, InstallDate, InstallLocation, HelpLink, Publisher, UninstallString, URLInfoAbout, Is64Bit, Hive, Path, Username, ComputerName 
}

function Get-DCVInformation {
    [CmdletBinding()]
    param()

    if (-not (Test-Path $script:DCVPath)) {
        Write-Warning "DCV executable not found at $script:DCVPath"
        return $null
    }

    try {
        $config = & $script:DCVPath get-config 2>$null
        $configAll = & $script:DCVPath get-config --all 2>$null
        
        $sessionsJson = & $script:DCVPath list-sessions --json 2>$null
        $sessions = if ($sessionsJson) { $sessionsJson | ConvertFrom-Json } else { $null }
        
        $connections = if ($sessions) {
            $connectionsJson = & $script:DCVPath list-connections console --json 2>$null
            if ($connectionsJson) { $connectionsJson | ConvertFrom-Json } else { $null }
        } else { $null }

        return @{
            Config = $config
            ConfigAll = $configAll
            Sessions = $sessions
            Connections = $connections
        }
    }
    catch {
        Write-Warning "Failed to retrieve DCV information: $_"
        return $null
    }
}

function Get-RecentWinEvents {
    [CmdletBinding()]
    param(
        [string]$DestinationPath,
        [int]$DaysBack = 7
    )
    
    # Calculate the date from which to copy logs
    $cutoffDate = (Get-Date).AddDays(-$DaysBack)
    $formattedDate = $cutoffDate.ToString("yyyy-MM-dd")
    Write-Verbose "Copying Windows Event logs from the last $DaysBack ($formattedDate) days"
    
    # Create destination directory if it doesn't exist
    if (-not (Test-Path -Path $DestinationPath)) {
        New-Item -Path $DestinationPath -ItemType Directory -Force | Out-Null
    }
    
    # Get all event log files
    $eventLogPath = "$Env:windir\System32\winevt\Logs"
    if (-not (Test-Path $eventLogPath)) {
        Write-Warning "Event log path not found: $eventLogPath"
        return
    }
    
    $eventLogFiles = Get-ChildItem -Path $eventLogPath -Filter "*.evtx" -ErrorAction SilentlyContinue
    
    $copiedCount = 0
    $skippedCount = 0
    
    foreach ($logFile in $eventLogFiles) {
        try {
            # Get the last write time of the log file
            $lastWriteTime = $logFile.LastWriteTime
            
            # Check if the log was modified within the specified time period
            if ($lastWriteTime -ge $cutoffDate) {
                Write-Verbose "Copying $($logFile.Name) - Last modified: $($lastWriteTime)"
                Copy-Item -Path $logFile.FullName -Destination $DestinationPath -Force -ErrorAction SilentlyContinue
                $copiedCount++
            } else {
                Write-Verbose "Skipping $($logFile.Name) - Last modified: $($lastWriteTime)"
                $skippedCount++
            }
        } catch {
            Write-Warning "Failed to process $($logFile.Name): $_"
        }
    }
    
    Write-Host "Event log copy complete. Copied $copiedCount files, skipped $skippedCount files."
}

function Get-RecentCrashDumps {
    [CmdletBinding()]
    param(
        [string]$DestinationPath,
        [int]$DaysBack = 7
    )
    
    # Calculate the date from which to copy crash dumps
    $cutoffDate = (Get-Date).AddDays(-$DaysBack)
    $formattedDate = $cutoffDate.ToString("yyyy-MM-dd")
    Write-Verbose "Collecting crash dumps from the last $DaysBack days ($formattedDate)"
    
    # Create destination directory if it doesn't exist
    if (-not (Test-Path -Path $DestinationPath)) {
        New-Item -Path $DestinationPath -ItemType Directory -Force | Out-Null
    }
    
    # Common crash dump locations
    $dumpLocations = @(
        "$env:SystemRoot\Minidump",
        "$env:SystemRoot\MEMORY.DMP",
        "$env:LocalAppData\CrashDumps",
        "$env:ProgramData\Microsoft\Windows\WER\ReportQueue",
        "$env:ProgramData\Microsoft\Windows\WER\ReportArchive",
        "$env:SystemRoot\LiveKernelReports",
        "$env:SystemRoot\System32\config\systemprofile\AppData\Local\CrashDumps"
    )
    
    $copiedCount = 0
    $skippedCount = 0
    
    foreach ($location in $dumpLocations) {
        if (Test-Path -Path $location) {
            if ((Get-Item $location) -is [System.IO.FileInfo]) {
                $dumpFile = Get-Item $location
                if ($dumpFile.LastWriteTime -ge $cutoffDate) {
                    try {
                        Write-Verbose "Copying crash dump file: $($dumpFile.FullName) - Last modified: $($dumpFile.LastWriteTime)"
                        Copy-Item -Path $dumpFile.FullName -Destination $DestinationPath -Force -ErrorAction SilentlyContinue
                        $copiedCount++
                    } catch {
                        Write-Warning "Failed to copy crash dump file $($dumpFile.FullName): $_"
                    }
                } else {
                    Write-Verbose "Skipping crash dump file: $($dumpFile.FullName) - Last modified: $($dumpFile.LastWriteTime)"
                    $skippedCount++
                }
            } 
            else {
                $dumpFiles = Get-ChildItem -Path $location -Recurse -File -Include "*.dmp", "*.mdmp", "*.hdmp", "*.kdmp", "*.cab" -ErrorAction SilentlyContinue
                
                foreach ($dumpFile in $dumpFiles) {
                    if ($dumpFile.LastWriteTime -ge $cutoffDate) {
                        try {
                            $relativePath = $dumpFile.DirectoryName.Replace($location, "").TrimStart("\")
                            $targetDir = Join-Path -Path $DestinationPath -ChildPath $relativePath
                            
                            if (-not (Test-Path -Path $targetDir)) {
                                New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
                            }
                            
                            Write-Verbose "Copying crash dump: $($dumpFile.FullName) - Last modified: $($dumpFile.LastWriteTime)"
                            Copy-Item -Path $dumpFile.FullName -Destination $targetDir -Force -ErrorAction SilentlyContinue
                            $copiedCount++
                        } catch {
                            Write-Warning "Failed to copy crash dump $($dumpFile.FullName): $_"
                        }
                    } else {
                        Write-Verbose "Skipping crash dump: $($dumpFile.FullName) - Last modified: $($dumpFile.LastWriteTime)"
                        $skippedCount++
                    }
                }
            }
        } else {
            Write-Verbose "Dump location does not exist: $location"
        }
    }
    
    Write-Host "Crash dump collection complete. Copied $copiedCount files, skipped $skippedCount files."
}

function New-LogBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    try {
        $script:HostnameBundlePath = Join-Path -Path $OutputPath -ChildPath "dcv_$script:Hostname"
        $script:BundlePath = Join-Path -Path $script:HostnameBundlePath -ChildPath $script:LogBundleName
        
        $null = New-Item -Path $script:BundlePath -ItemType Directory -Force

        # Product-identification manifest so downstream tools (e.g. the AI Log
        # Analysis service) can reliably detect what this bundle is.
        try {
            $meta = [ordered]@{
                product          = 'dcv-windows'
                script_version   = $script:CollectionScriptVersion
                hostname         = $script:Hostname
                collected_at_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                schema           = 1
            }
            $meta | ConvertTo-Json | Set-Content -Path (Join-Path $script:BundlePath 'collection_meta.json') -Encoding UTF8
        }
        catch {
            Write-Warning "Failed to write collection_meta.json: $_"
        }

        Write-ColoredOutput "Collecting log bundle information..." "Green"

        try {
            Write-Host "Collecting EC2 metadata..."
            $metadata = Get-EC2InstanceMetadata
            if ($metadata) {
                $metadata | ConvertTo-Json | Set-Content -Path (Join-Path $script:BundlePath 'metadata.json')
            }
        }
        catch {
            Write-Warning "Not running on EC2 or failed to retrieve metadata"
        }

        Write-Host "Collecting installed applications..."
        try {
            Get-InstalledApplications | Export-Csv -Path (Join-Path $script:BundlePath 'installedApps.csv') -NoTypeInformation
        }
        catch {
            Write-Warning "Failed to collect installed applications: $_"
        }

        # Conditionally collect GPO results based on user consent
        if ($script:CollectGpoResults) {
            Write-Host "Collecting Group Policy results..."
            try {
                $gpResultPath = Join-Path $script:BundlePath 'GPResult.html'
                
                $gpresultSuccess = $false
                
                try {
                    Start-Process -FilePath "gpresult" -ArgumentList "/H", "`"$gpResultPath`"" -Wait -NoNewWindow -ErrorAction Stop
                    $gpresultSuccess = $true
                    Write-Host "Group Policy results collected successfully (HTML format)"
                }
                catch {
                    Write-Verbose "Failed with /H parameter: $_"
                }
                
                if (-not $gpresultSuccess) {
                    try {
                        Start-Process -FilePath "gpresult" -ArgumentList "/h", "`"$gpResultPath`"" -Wait -NoNewWindow -ErrorAction Stop
                        $gpresultSuccess = $true
                        Write-Host "Group Policy results collected successfully (HTML format)"
                    }
                    catch {
                        Write-Verbose "Failed with /h parameter: $_"
                    }
                }
                
                if (-not $gpresultSuccess) {
                    try {
                        $gpResultTextPath = Join-Path $script:BundlePath 'GPResult.txt'
                        Start-Process -FilePath "gpresult" -ArgumentList "/R" -Wait -NoNewWindow -RedirectStandardOutput $gpResultTextPath -ErrorAction Stop
                        Write-Host "Group Policy results collected successfully (text format)"
                    }
                    catch {
                        Write-Warning "Failed to collect Group Policy results with all methods: $_"
                    }
                }
            }
            catch {
                Write-Warning "Failed to collect Group Policy results: $_"
            }
        }
        else {
            Write-Host "Skipping Group Policy results collection as requested by user."
        }

        Write-Host "Collecting DCV information..."
        $dcvInfo = Get-DCVInformation
        if ($dcvInfo) {
            foreach ($item in $dcvInfo.GetEnumerator()) {
                if ($item.Value) {
                    try {
                        $item.Value | ConvertTo-Json | Set-Content -Path (Join-Path $script:BundlePath "DCV$($item.Key).json")
                    }
                    catch {
                        Write-Warning "Failed to save DCV $($item.Key) information: $_"
                    }
                }
            }
        }

        try {
            Write-Host "Collecting Windows Event Logs..."
            $eventLogsPath = Join-Path -Path $script:BundlePath -ChildPath "EventLogs"
            Get-RecentWinEvents -DestinationPath $eventLogsPath -DaysBack 7 -Verbose
        }
        catch {
            Write-Warning "Failed to copy recent Windows Event Logs: $_"
        }

        try {
            Write-Host "Collecting Windows Crash Dumps..."
            $crashDumpsPath = Join-Path -Path $script:BundlePath -ChildPath "CrashDumps"
            Get-RecentCrashDumps -DestinationPath $crashDumpsPath -DaysBack 7 -Verbose
        }
        catch {
            Write-Warning "Failed to copy recent Windows Crash Dumps: $_"
        }

        try {
            Write-Host "Collecting DCV logs..."
            $dcvLogsPath = "C:\Program Files\NICE\"
            if (Test-Path $dcvLogsPath) {
                $dcvDestPath = Join-Path $script:BundlePath "NICE"
                Copy-Item -Path $dcvLogsPath -Destination $dcvDestPath -Recurse -ErrorAction SilentlyContinue
            }
            else {
                Write-Warning "DCV logs path not found: $dcvLogsPath"
            }
        }
        catch {
            Write-Warning "Unable to copy DCV log folder: $_"
        }

        # NEW: Collect ProgramData\NICE directory
        try {
            Write-Host "Collecting ProgramData NICE directory..."
            $programDataNicePath = "C:\ProgramData\NICE"
            if (Test-Path $programDataNicePath) {
                $programDataNiceDestPath = Join-Path $script:BundlePath "ProgramData_NICE"
                Copy-Item -Path $programDataNicePath -Destination $programDataNiceDestPath -Recurse -ErrorAction SilentlyContinue
                Write-Host "ProgramData NICE directory collected successfully"
            }
            else {
                Write-Host "ProgramData NICE directory not found: $programDataNicePath"
            }
        }
        catch {
            Write-Warning "Failed to copy ProgramData NICE directory: $_"
        }

        # NEW: Collect C:\ProgramData\client.log file
        try {
            Write-Host "Collecting ProgramData client.log file..."
            $clientLogPath = "C:\ProgramData\client.log"
            if (Test-Path $clientLogPath) {
                $clientLogDestPath = Join-Path $script:BundlePath "client.log"
                Copy-Item -Path $clientLogPath -Destination $clientLogDestPath -ErrorAction SilentlyContinue
                Write-Host "ProgramData client.log file collected successfully"
            }
            else {
                Write-Host "ProgramData client.log file not found: $clientLogPath"
            }
        }
        catch {
            Write-Warning "Failed to copy ProgramData client.log file: $_"
        }

        # NEW: Export registry entries from HKEY_USERS/S-1-5-18/Software/GSettings/com/nicesoftware
        try {
            Write-Host "Collecting NICE GSettings registry entries..."
            $regPath = "HKU\S-1-5-18\Software\GSettings\com\nicesoftware"
            $regExportPath = Join-Path $script:BundlePath "NICE_GSettings_Registry.reg"
            
            # First check if the registry path exists
            $regKeyExists = $false
            try {
                $regTestResult = reg query "HKU\S-1-5-18\Software\GSettings\com\nicesoftware" 2>$null
                if ($LASTEXITCODE -eq 0) {
                    $regKeyExists = $true
                }
            }
            catch {
                # Ignore errors from reg query
            }
            
            if ($regKeyExists) {
                try {
                    $regExportResult = reg export $regPath $regExportPath /y 2>$null
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "NICE GSettings registry entries exported successfully"
                    }
                    else {
                        Write-Host "Registry export command completed but may have encountered issues"
                    }
                }
                catch {
                    Write-Warning "Failed to export NICE GSettings registry entries: $_"
                }
            }
            else {
                Write-Host "NICE GSettings registry path not found: $regPath"
            }
        }
        catch {
            Write-Warning "Failed to collect NICE GSettings registry entries: $_"
        }

        try {
            Write-Host "Collecting system information..."
            $systemInfoPath = Join-Path $script:BundlePath "SystemInfo.txt"
            $systemInfo = systeminfo 2>$null
            $systemInfo | Set-Content -Path $systemInfoPath
        }
        catch {
            Write-Warning "Failed to collect system information: $_"
        }

        try {
            $windowsVersionPath = Join-Path $script:BundlePath "WindowsVersion.json"
            Get-ComputerInfo | ConvertTo-Json | Set-Content -Path $windowsVersionPath
        }
        catch {
            Write-Warning "Failed to collect Windows version information: $_"
        }

        try {
            Write-Host "Collecting network information..."
            $networkPath = Join-Path $script:BundlePath "NetworkInfo.txt"
            $networkInfo = @()
            $networkInfo += "=== IP Configuration ==="
            $networkInfo += ipconfig /all 2>$null
            $networkInfo += ""
            $networkInfo += "=== Network Statistics ==="
            $networkInfo += netstat -an 2>$null
            $networkInfo | Set-Content -Path $networkPath
        }
        catch {
            Write-Warning "Failed to collect network information: $_"
        }

        Write-ColoredOutput "Log bundle created successfully" "Green"
    }
    catch {
        Write-Error "Failed to create log bundle: $_"
    }
}

# Before compressing, drop any individual crash dump or event log file that is
# larger than the given threshold (default 30 MB). Large single files rarely add
# troubleshooting value and bloat the bundle; smaller ones are kept.
function Remove-OversizedLogFiles {
    param(
        [int]$MaxSizeMB = 30
    )

    $maxBytes = $MaxSizeMB * 1MB
    $targets = @(
        (Join-Path -Path $script:HostnameBundlePath -ChildPath "CrashDumps"),
        (Join-Path -Path $script:HostnameBundlePath -ChildPath "EventLogs")
    )

    foreach ($target in $targets) {
        if (-not (Test-Path $target)) { continue }

        $oversized = Get-ChildItem -Path $target -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt $maxBytes }

        foreach ($file in $oversized) {
            $sizeMB = [math]::Round($file.Length / 1MB, 2)
            Write-ColoredOutput "Removing oversized file ($sizeMB MB, > $MaxSizeMB MB): $($file.Name)" "Yellow"
            Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-LogCompression {
    try {
        $zipPath = Join-Path -Path $PSScriptRoot -ChildPath $script:CompressedFileName

        if ($script:SkipEncryption) {
            # --without-encryption: produce a plain ZIP with no password.
            Write-ColoredOutput "Compressing log collection (no encryption)..." "Green"
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
            [System.IO.Compression.ZipFile]::CreateFromDirectory($script:HostnameBundlePath, $zipPath)
            $script:EncryptPassword = ""
            Write-ColoredOutput "Compression completed successfully (unencrypted)" "Green"
            return
        }

        $script:EncryptPassword = Generate-RandomPassword -Length 32

        Write-ColoredOutput "Compressing log collection..." "Green"
        $success = New-PasswordProtectedZip -SourcePath $script:HostnameBundlePath -DestinationPath $zipPath -Password $script:EncryptPassword

        if ($success) {
            Write-ColoredOutput "Compression completed successfully" "Green"
        }
        else {
            Write-Error "Failed to compress log collection"
        }
    }
    catch {
        Write-Error "Failed to compress log collection: $_"
    }
}

# Main execution
function Main {
    try {
        Show-WelcomeMessage
        New-LogBundle -OutputPath $PSScriptRoot

        # --without-compression: keep the logs as a plain directory and stop here.
        # (This mode also implies --without-encryption and --without-upload.)
        if ($script:SkipCompression) {
            Write-ColoredOutput "Skipping compression (--without-compression)." "Yellow"
            Write-ColoredOutput "Logs were kept as a directory at:" "Green"
            Write-ColoredOutput $script:HostnameBundlePath "Green"
            Show-ByeByeMessage
            return
        }

        # Drop any crash dump / event log file over 30 MB before compressing.
        Remove-OversizedLogFiles -MaxSizeMB 30

        Invoke-LogCompression

        $zipPath = Join-Path -Path $PSScriptRoot -ChildPath $script:CompressedFileName
        if (Test-Path $zipPath) {
            $zipSizeMB = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
            if ($zipSizeMB -gt 500 -and -not $script:NonInteractive) {
                Write-ColoredOutput "The compressed file is $zipSizeMB MB." "Yellow"
                Write-ColoredOutput "Would you like to remove Crash Dumps and Event Logs to reduce the file size? (Y/N):" "Yellow"
                $reduceConfirm = Read-Host
                if ($reduceConfirm -match "^(Y|y|Yes|yes)$") {
                    Write-ColoredOutput "Removing Crash Dumps and Event Logs from the bundle..." "Yellow"
                    $eventLogsPath = Join-Path -Path $script:HostnameBundlePath -ChildPath "EventLogs"
                    $crashDumpsPath = Join-Path -Path $script:HostnameBundlePath -ChildPath "CrashDumps"
                    if (Test-Path $eventLogsPath) { Remove-Item -Path $eventLogsPath -Recurse -Force }
                    if (Test-Path $crashDumpsPath) { Remove-Item -Path $crashDumpsPath -Recurse -Force }

                    Remove-Item -Path $zipPath -Force
                    $passwordFile = [System.IO.Path]::ChangeExtension($zipPath, ".password.txt")
                    if (Test-Path $passwordFile) { Remove-Item -Path $passwordFile -Force }

                    Write-ColoredOutput "Re-compressing log collection..." "Green"
                    Invoke-LogCompression

                    if (Test-Path $zipPath) {
                        $newSizeMB = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
                        Write-ColoredOutput "New file size: $newSizeMB MB" "Green"
                    }
                }
            }
            if (Test-Path $zipPath) {
                if ($script:SkipUpload) {
                    Write-ColoredOutput "Skipping upload (--without-upload). File saved locally at:" "Yellow"
                    Write-ColoredOutput $zipPath "Green"
                    Write-ColoredOutput "You can upload it manually to: $script:UploadServiceBase/" "Green"
                    Write-ColoredOutput "then use the 'Ask Deep NI SP to analyze these logs' button." "Green"
                }
                else {
                    Invoke-SendToSupport -FilePath $zipPath
                }
            }
        }

        Remove-TempFiles
        Show-ByeByeMessage
    }
    catch {
        Write-Error "Script execution failed: $_"
        exit 1
    }
}

# ---------------------------------------------------------------------------
# Parameter parsing (GNU double-dash style flags, read from the $args variable)
# ---------------------------------------------------------------------------
$ShowHelp = $false

for ($i = 0; $i -lt $args.Count; $i++) {
    $arg = [string]$args[$i]
    switch -Regex ($arg) {
        '^--without-upload$'      { $script:SkipUpload = $true; break }
        '^--without-encryption$'  { $script:SkipEncryption = $true; break }
        '^--collect-logs$'        { $script:NonInteractive = $true; break }
        '^--without-compression$' { $script:SkipCompression = $true; break }
        '^--proxy$'               { $i++; $script:ProxyUrl = [string]$args[$i]; break }
        '^--proxy=.*$'            { $script:ProxyUrl = $arg.Substring('--proxy='.Length); break }
        '^--message$'             { $i++; $script:Message = [string]$args[$i]; break }
        '^--message=.*$'          { $script:Message = $arg.Substring('--message='.Length); break }
        '^--name$'                { $i++; $script:SupportName = [string]$args[$i]; break }
        '^--name=.*$'             { $script:SupportName = $arg.Substring('--name='.Length); break }
        '^--email$'               { $i++; $script:SupportEmail = [string]$args[$i]; break }
        '^--email=.*$'            { $script:SupportEmail = $arg.Substring('--email='.Length); break }
        '^--problem$'             { $i++; $script:SupportProblem = [string]$args[$i]; break }
        '^--problem=.*$'          { $script:SupportProblem = $arg.Substring('--problem='.Length); break }
        '^(--help|-h|-\?|/\?)$'   { $ShowHelp = $true; break }
        '^(--force|-Force)$'      { break }  # accepted for backward compatibility (no-op)
        default {
            Write-ColoredOutput "Unknown parameter: $arg" "Red"
            $ShowHelp = $true
        }
    }
}

if ($ShowHelp) {
    Show-Help
    exit 0
}

# --without-compression implies --without-encryption and --without-upload.
if ($script:SkipCompression) {
    $script:SkipEncryption = $true
    $script:SkipUpload = $true
}

# The AI analysis reads the logs, so the uploaded bundle is always unencrypted.
$script:SkipEncryption = $true

# --message is a deprecated alias for the problem description.
if (-not [string]::IsNullOrWhiteSpace($script:Message) -and [string]::IsNullOrWhiteSpace($script:SupportProblem)) {
    $script:SupportProblem = $script:Message
}

Main
