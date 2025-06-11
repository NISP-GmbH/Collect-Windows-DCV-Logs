# Collect Windows DCV Logs

This script was created to help you collect all relevant logs to troubleshoot any DCV issue.

After collect the data, you will be asked if you want to securely send the file to NI-SP Cloud or if you want to send it manually.

# How to execute:

Open the Powershell terminal with Administrator rights. Then you need to execute:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/NISP-GmbH/Collect-Windows-DCV-Logs/main/Collect-Windows-DCV-Logs.ps1" -OutFile "$env:TEMP\Collect-Windows-DCV-Logs.ps1"; Unblock-File -Path "$env:TEMP\Collect-Windows-DCV-Logs.ps1"; & "$env:TEMP\Collect-Windows-DCV-Logs.ps1"
```
