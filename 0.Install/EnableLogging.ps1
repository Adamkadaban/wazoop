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
auditpol /set /Category:"Object Access" /Subcategory:"Certification Services" /success:enable /failure:enable

# Enable Process Execution Logging
auditpol /set /Category:"Detailed Tracking" /Subcategory:"Process Creation" /success:enable /failure:enable

# Enable Account Logon/Logoff Logging
auditpol /set /Category:"Logon/Logoff" /Subcategory:"Logon" /success:enable /failure:enable
auditpol /set /Category:"Logon/Logoff" /Subcategory:"Logoff" /success:enable /failure:enable

# Enable File System Object Auditing
auditpol /set /Category:"Object Access" /Subcategory:"File System" /success:enable /failure:enable

# Enable Kerberos Logging
auditpol /set /Category:"Account Logon" /Subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /Category:"Account Logon" /Subcategory:"Kerberos Authentication Service" /success:enable /failure:enable

# Enable Event Log Access Auditing
auditpol /set /Category:"System" /Subcategory:"System Integrity" /success:enable /failure:enable
