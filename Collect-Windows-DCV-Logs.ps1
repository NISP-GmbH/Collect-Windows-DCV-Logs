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

[CmdletBinding()]
param(
    [switch]$Force
)

# Add required assemblies
Add-Type -AssemblyName System.Web

# Constants
$script:DCVPath = 'C:\Program Files\NICE\DCV\Server\bin\dcv.exe'
$script:MetadataBaseUrl = 'http://169.254.169.254/latest'
$script:LogBundleName = 'DCVLogBundle'
$script:Hostname = $env:COMPUTERNAME
$script:CompressedFileName = "dcv_logs_collection_$($script:Hostname).zip"
$script:UploadDomain = 'https://dcv-logs.ni-sp.com'
$script:UploadUrl = "$script:UploadDomain/upload.php"
$script:NotifyUrl = "$script:UploadDomain/notify.php"

# Global variables
$script:IdentifierString = ""
$script:EncryptPassword = ""
$script:BundlePath = ""
$script:HostnameBundlePath = ""
$script:CollectGpoResults = $false # Default to not collecting GPO

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

function Show-WelcomeMessage {
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
    Write-Host "Write any text that will identify you for NISP Support Team. Can be e-mail, name, e-mail subject, company name etc."
    Write-ColoredOutput "(This field is required)" "Yellow"
    
    do {
        $script:IdentifierString = Read-Host
        if ([string]::IsNullOrWhiteSpace($script:IdentifierString)) {
            Write-ColoredOutput "Identifier is required. Please enter a valid identifier." "Red"
        }
    } while ([string]::IsNullOrWhiteSpace($script:IdentifierString))

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
            Compress-Archive -Path "$SourcePath\*" -DestinationPath $DestinationPath -Force
            
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

function Invoke-LogUpload {
    param(
        [string]$FilePath
    )
    
    $fileInfo = Get-Item $FilePath
    $fileSizeMB = [math]::Round($fileInfo.Length / 1MB, 2)
    Write-Host "File size: $fileSizeMB MB"
    
    if ($fileSizeMB -gt 100) {
        Write-ColoredOutput "Warning: File is larger than 100MB. Upload may take longer or fail." "Yellow"
        Write-ColoredOutput "Do you want to continue with upload? (Y/N):" "Yellow"
        $uploadConfirm = Read-Host
        if ($uploadConfirm -notmatch "^(Y|y|Yes|yes)$") {
            Write-ColoredOutput "Upload cancelled. File saved locally." "Yellow"
            return
        }
    }
    
    # Test basic connectivity first
    try {
        Write-Host "Testing connectivity to $script:UploadDomain..."
        $testResponse = Invoke-WebRequest -Uri $script:UploadDomain -Method HEAD -TimeoutSec 10 -UseBasicParsing
        Write-ColoredOutput "Connectivity test successful" "Green"
    }
    catch {
        Write-Warning "Connectivity test failed: $_"
        Write-ColoredOutput "Unable to connect to upload server. Please check your internet connection." "Red"
        return
    }
    
    $maxRetries = 3
    $retryCount = 0
    
    while ($retryCount -lt $maxRetries) {
        try {
            Write-ColoredOutput "Attempt $($retryCount + 1) of $maxRetries - Uploading file to NISP Support Team..." "Green"
            
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
            [Net.ServicePointManager]::Expect100Continue = $false
            [Net.ServicePointManager]::UseNagleAlgorithm = $false
            [Net.ServicePointManager]::CheckCertificateRevocationList = $false
            
            # Read file content
            $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
            $fileName = [System.IO.Path]::GetFileName($FilePath)
            
            Write-Host "Uploading... Please wait (this may take several minutes for large files)"
            
            # Method 1: Try with Add-Type and HttpClient (more reliable for large files)
            try {
                Add-Type -AssemblyName System.Net.Http
                
                $httpClient = New-Object System.Net.Http.HttpClient
                $httpClient.Timeout = [TimeSpan]::FromMinutes(10)
                
                $multipartContent = New-Object System.Net.Http.MultipartFormDataContent
                
                # Add service parameter (dcv for DCV logs)
                $serviceContent = New-Object System.Net.Http.StringContent -ArgumentList @("dcv")
                $multipartContent.Add($serviceContent, "service")
                
                # Add identifier parameter
                $identifierContent = New-Object System.Net.Http.StringContent -ArgumentList @($script:IdentifierString)
                $multipartContent.Add($identifierContent, "identifier")
                
                # Add file content
                $fileContent = New-Object System.Net.Http.ByteArrayContent -ArgumentList @(,$fileBytes)
                $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("application/octet-stream")
                $multipartContent.Add($fileContent, "file", $fileName)
                
                $response = $httpClient.PostAsync($script:UploadUrl, $multipartContent).Result
                $responseContent = $response.Content.ReadAsStringAsync().Result
                
                $httpClient.Dispose()
                $multipartContent.Dispose()
                $fileContent.Dispose()
                
                if ($response.IsSuccessStatusCode -and $responseContent) {
                    Write-ColoredOutput "Upload successful using HttpClient!" "Green"
                    
                    # Notify NISP Support Team
                    try {
                        $notifyData = @{
                            encrypt_password = $script:EncryptPassword
                            curl_filename = $responseContent.Trim()
                            identifier_string = $script:IdentifierString
                        }
                        
                        $notifyResponse = Invoke-RestMethod -Uri $script:NotifyUrl -Method Post -Body $notifyData -ContentType "application/x-www-form-urlencoded" -TimeoutSec 30
                        Write-ColoredOutput "NISP Support Team was notified about the file!" "Green"
                    }
                    catch {
                        Write-ColoredOutput "Failed to notify the NISP Support Team. Please send an e-mail." "Yellow"
                        Write-Warning "Notification error: $_"
                    }
                    return
                }
                else {
                    throw "HttpClient upload failed: $($response.StatusCode) - $responseContent"
                }
            }
            catch {
                Write-Warning "HttpClient method failed: $_"
                
                # Method 2: Fallback to WebClient with proper configuration
                try {
                    $webClient = New-Object System.Net.WebClient
                    $webClient.Headers.Add("User-Agent", "PowerShell-DCVLogCollector/1.0")
                    
                    # Create proper multipart form data
                    $boundary = [System.Guid]::NewGuid().ToString()
                    $webClient.Headers.Add("Content-Type", "multipart/form-data; boundary=$boundary")
                    
                    $LF = "`r`n"
                    $bodyLines = @()
                    
                    # Add service parameter
                    $bodyLines += "--$boundary"
                    $bodyLines += "Content-Disposition: form-data; name=`"service`""
                    $bodyLines += ""
                    $bodyLines += "dcv"
                    
                    # Add identifier parameter
                    $bodyLines += "--$boundary"
                    $bodyLines += "Content-Disposition: form-data; name=`"identifier`""
                    $bodyLines += ""
                    $bodyLines += $script:IdentifierString
                    
                    # Add file content
                    $bodyLines += "--$boundary"
                    $bodyLines += "Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`""
                    $bodyLines += "Content-Type: application/octet-stream"
                    $bodyLines += ""
                    
                    # Convert to bytes properly
                    $encoding = [System.Text.Encoding]::GetEncoding("iso-8859-1")
                    $bodyBytes = $encoding.GetBytes(($bodyLines -join $LF) + $LF)
                    $bodyBytes += $fileBytes
                    $bodyBytes += $encoding.GetBytes($LF + "--$boundary--" + $LF)
                    
                    $response = $webClient.UploadData($script:UploadUrl, "POST", $bodyBytes)
                    $responseText = $encoding.GetString($response)
                    
                    $webClient.Dispose()
                    
                    if ($responseText) {
                        Write-ColoredOutput "Upload successful using WebClient!" "Green"
                        
                        # Notify NISP Support Team
                        try {
                            $notifyData = @{
                                encrypt_password = $script:EncryptPassword
                                curl_filename = $responseText.Trim()
                                identifier_string = $script:IdentifierString
                            }
                            
                            $notifyResponse = Invoke-RestMethod -Uri $script:NotifyUrl -Method Post -Body $notifyData -ContentType "application/x-www-form-urlencoded" -TimeoutSec 30
                            Write-ColoredOutput "NISP Support Team was notified about the file!" "Green"
                        }
                        catch {
                            Write-ColoredOutput "Failed to notify the NISP Support Team. Please send an e-mail." "Yellow"
                            Write-Warning "Notification error: $_"
                        }
                        return
                    }
                    else {
                        throw "WebClient upload returned empty response"
                    }
                }
                catch {
                    Write-Warning "WebClient method also failed: $_"
                    
                    # Method 3: Last resort - try curl if available
                    $curlPath = Get-Command "curl.exe" -ErrorAction SilentlyContinue
                    if ($curlPath) {
                        try {
                            Write-Host "Trying with curl as last resort..."
                            
                            $curlArgs = @(
                                "-X", "POST"
                                "-F", "service=dcv"
                                "-F", "identifier=$($script:IdentifierString)"
                                "-F", "file=@`"$FilePath`""
                                "--connect-timeout", "30"
                                "--max-time", "600"
                                "--retry", "2"
                                "--retry-delay", "5"
                                "--user-agent", "PowerShell-DCVLogCollector/1.0"
                                $script:UploadUrl
                            )
                            
                            $curlResult = & $curlPath.Source @curlArgs 2>&1
                            
                            if ($LASTEXITCODE -eq 0 -and $curlResult) {
                                Write-ColoredOutput "Upload successful using curl!" "Green"
                                
                                # Notify NISP Support Team
                                try {
                                    $notifyData = @{
                                        encrypt_password = $script:EncryptPassword
                                        curl_filename = $curlResult.ToString().Trim()
                                        identifier_string = $script:IdentifierString
                                    }
                                    
                                    $notifyResponse = Invoke-RestMethod -Uri $script:NotifyUrl -Method Post -Body $notifyData -ContentType "application/x-www-form-urlencoded" -TimeoutSec 30
                                    Write-ColoredOutput "NISP Support Team was notified about the file!" "Green"
                                }
                                catch {
                                    Write-ColoredOutput "Failed to notify the NISP Support Team. Please send an e-mail." "Yellow"
                                    Write-Warning "Notification error: $_"
                                }
                                return
                            }
                            else {
                                throw "curl upload failed: $curlResult"
                            }
                        }
                        catch {
                            throw "All upload methods failed. Last error from curl: $_"
                        }
                    }
                    else {
                        throw "All upload methods failed and curl is not available"
                    }
                }
            }
        }
        catch {
            $retryCount++
            Write-Warning "Upload attempt $retryCount failed: $_"
            
            if ($retryCount -lt $maxRetries) {
                $waitTime = $retryCount * 5
                Write-ColoredOutput "Waiting $waitTime seconds before retry..." "Yellow"
                Start-Sleep -Seconds $waitTime
            }
            else {
                Write-Error "Failed to upload file after $maxRetries attempts: $_"
                Write-ColoredOutput "You can manually send the file to NISP Support Team." "Yellow"
                
                # Show file location for manual sending
                if (Test-Path $FilePath) {
                    Write-ColoredOutput "File location: $FilePath" "Yellow"
                    $passwordFile = [System.IO.Path]::ChangeExtension($FilePath, ".password.txt")
                    if (Test-Path $passwordFile) {
                        Write-ColoredOutput "Password file: $passwordFile" "Yellow"
                    }
                }
            }
        }
    }
}

function Remove-TempFiles {
    Write-Host "Cleaning temp files..."
    
    $zipPath = Join-Path -Path $PSScriptRoot -ChildPath $script:CompressedFileName
    
    if (Test-Path $zipPath) {
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

function Invoke-LogCompression {
    try {
        $script:EncryptPassword = Generate-RandomPassword -Length 32
        $zipPath = Join-Path -Path $PSScriptRoot -ChildPath $script:CompressedFileName
        
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
        Invoke-LogCompression
        
        $zipPath = Join-Path -Path $PSScriptRoot -ChildPath $script:CompressedFileName
        if (Test-Path $zipPath) {
            Invoke-LogUpload -FilePath $zipPath
        }
        
        Remove-TempFiles
        Show-ByeByeMessage
    }
    catch {
        Write-Error "Script execution failed: $_"
        exit 1
    }
}

Main
