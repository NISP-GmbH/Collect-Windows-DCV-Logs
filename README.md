# Collect Windows DCV Logs

This script was created to help you collect all relevant logs to troubleshoot any DCV issue.

After collect the data, you will be asked if you want to securely send the file to NI-SP Cloud or if you want to send it manually.

# How to execute:

Open the Powershell terminal with Administrator rights. Then you need to execute:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/NISP-GmbH/Collect-Windows-DCV-Logs/main/Collect-Windows-DCV-Logs.ps1" -OutFile "$env:TEMP\Collect-Windows-DCV-Logs.ps1"; Unblock-File -Path "$env:TEMP\Collect-Windows-DCV-Logs.ps1"; & "$env:TEMP\Collect-Windows-DCV-Logs.ps1"
```

# Illustration

First you execute the script and write something to identify you to NI-SP.

![Image](https://github.com/user-attachments/assets/8a4034bf-a480-412e-a4dd-1fc8f017669b)

Then wait the log collecion execution and, in the end, you can delete or save the data collected.

![Image](https://github.com/user-attachments/assets/ddbd842c-58b1-4f5d-aa4a-6ff0e2aea88c)
