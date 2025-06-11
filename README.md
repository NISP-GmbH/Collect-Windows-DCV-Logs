# Collect Windows DCV Logs

This script was created to help you collect all relevant logs to troubleshoot any DCV issue.

After collect the data, you will be asked if you want to securely send the file to NI-SP Cloud or if you want to send it manually.

# How to execute:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
Unblock-File -Path .\Collect-Windows-DCV-Logs.ps1

.\Collect-Windows-DCV-Logs.ps1
```
