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
auditpol /set /Subcategory:"Certification Services" /success:enable /failure:enable

# Enable Process Execution Logging
auditpol /set /Subcategory:"Process Creation" /success:enable /failure:enable

# Enable Account Logon/Logoff Logging
auditpol /set /Subcategory:"Logon" /success:enable /failure:enable
auditpol /set /Subcategory:"Logoff" /success:enable /failure:enable

# Enable File System Object Auditing
auditpol /set /Subcategory:"File System" /success:enable /failure:enable

# Enable Kerberos Logging
auditpol /set /Subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /Subcategory:"Kerberos Authentication Service" /success:enable /failure:enable

# Enable Event Log Access Auditing
auditpol /set /Subcategory:"System Integrity" /success:enable /failure:enable
