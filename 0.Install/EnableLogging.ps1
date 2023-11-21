# Enable Powershell Logging
## Script Block Logging
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
## Transcription Logging
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription /v EnableTranscription /t REG_DWORD /d 1 /f


