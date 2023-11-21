#######################################################
# Enable Logging to make sure we see things in sysmon #
#######################################################

#--------------------------------------#
# Event ID 4719 is audit policy change #
#--------------------------------------#

# Enable Powershell Logging
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription /v EnableTranscription /t REG_DWORD /d 1 /f

# Enable ADCS Auditing
auditpol /set /Category:"Object Access" /subcategory:"Certification Services" /success:enable /failure:enable

# Enable Process Execution Logging
auditpol /set /Category:"Detailed Tracking" /subcategory:"Process Creation" /success:enable /failure:enable
