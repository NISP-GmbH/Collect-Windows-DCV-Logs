# Collect Windows DCV Logs

This script was created to help you collect all relevant logs to troubleshoot any DCV issue.

After collect the data, you will be asked if you want to securely send the file to NI-SP Cloud or if you want to send it manually.

# How to execute:

Open the Powershell terminal with Administrator rights. Then you need to execute:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/NISP-GmbH/Collect-Windows-DCV-Logs/main/Collect-Windows-DCV-Logs.ps1" -OutFile "$env:TEMP\Collect-Windows-DCV-Logs.ps1"; Unblock-File -Path "$env:TEMP\Collect-Windows-DCV-Logs.ps1"; & "$env:TEMP\Collect-Windows-DCV-Logs.ps1"
```

Run it without any options for the default interactive experience.

# Command-line options

The script can also be run unattended using the following options:

| Option | Description |
| --- | --- |
| `--without-upload` | Skip upload; keep the file locally for manual upload. |
| `--without-encryption` | Create the compressed file without encryption. On Windows this produces a plain ZIP without a password (this script does not use GPG). |
| `--collect-logs` | Only collect logs (no interactive menu / prompts). |
| `--report-only` | _Not available — this script has no separate report mode._ |
| `--proxy <url>` | Use a proxy for uploading (e.g. `http://proxy:8080`, `socks5://proxy:1080`). |
| `--message <text>` | Identifier text for the NI SP Support Team (e.g. e-mail, name, company); skips the interactive prompt. |
| `--without-compression` | Skip compression (keeps logs as a directory). Also implicitly sets `--without-encryption` and `--without-upload`. |
| `--help`, `-h` | Show the help message and exit. |

In non-interactive mode (`--collect-logs`), if no `--message` is provided the
script falls back to a default identifier of `<hostname>_<timestamp>`. Group
Policy (GPO) results are **not** collected unattended, since they can be sensitive.

### Examples

```powershell
# Interactive run (default behaviour)
.\Collect-Windows-DCV-Logs.ps1

# Fully unattended collection + upload with a known identifier
.\Collect-Windows-DCV-Logs.ps1 --collect-logs --message "jane@acme.com"

# Collect and keep the file locally, no upload
.\Collect-Windows-DCV-Logs.ps1 --collect-logs --without-upload

# Collect raw logs as a plain directory (no zip, no encryption, no upload)
.\Collect-Windows-DCV-Logs.ps1 --collect-logs --without-compression

# Upload through a proxy
.\Collect-Windows-DCV-Logs.ps1 --collect-logs --message "me" --proxy "http://proxy:8080"
```

# Illustration

First you execute the script and write something to identify you to NI-SP.

![Image](https://github.com/user-attachments/assets/8a4034bf-a480-412e-a4dd-1fc8f017669b)

Then wait the log collecion execution and, in the end, you can delete or save the data collected.

![Image](https://github.com/user-attachments/assets/ddbd842c-58b1-4f5d-aa4a-6ff0e2aea88c)
