# Tested on Windows Server 2016, 2019, 2022

# Enable Powershell Logging
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription /v EnableTranscription /t REG_DWORD /d 1 /f


########################################################
# Enable Auditing to make sure we see things in sysmon #
########################################################
# https://serverfault.com/questions/617713/advanced-audit-policy-not-getting-applied-on-2012-r2


#--------------------------------------#
# Event ID 4719 is audit policy change #
#--------------------------------------#
# https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-audit-policy-change


auditpol /clear /y

# First, we need to set local policy with auditpol

## Enable ADCS Auditing
auditpol /set /Subcategory:"Certification Services" /success:enable /failure:enable

## Enable Process Execution Logging
auditpol /set /Subcategory:"Process Creation" /success:enable /failure:enable

## Enable Account Logon/Logoff Logging
auditpol /set /Subcategory:"Logon" /success:enable /failure:enable
auditpol /set /Subcategory:"Logoff" /success:enable /failure:enable

## Enable File System Object Auditing
auditpol /set /Subcategory:"File System" /success:enable /failure:enable

## Enable Kerberos Logging
auditpol /set /Subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /Subcategory:"Kerberos Authentication Service" /success:enable /failure:enable

## Enable Event Log Access Auditing
auditpol /set /Subcategory:"System Integrity" /success:enable /failure:enable

## Enable Group Change Auditing
auditpol /set /Subcategory:"Security Group Management" /success:enable /failure:enable

## Enable Group Membership Auditing
auditpol /set /Subcategory:"Security Group Management" /success:enable /failure:enable

## Enable User Permission Auditing
auditpol /set /Subcategory:"User Account Management" /success:enable /failure:enable

## Enable DCSync Auditing
auditpol /set /Subcategory:"Directory Service Replication" /success:enable /failure:enable
# auditpol /set /Subcategory:"Detailed Directory Service Replication" /success:enable /failure:enable

## Enable Task Scheduler History
wevtutil set-log Microsoft-Windows-TaskScheduler/Operational /enabled:true

# Now, we backup the local policy and set it to the group policy 

$hostname = [System.Net.Dns]::GetHostName()
$temp_path = "C:\Users\Administrator\AppData\Local\Temp" # This is probs not good, but I couldn't figure out how to resolve 8.3 paths in powershell

$directoryPath = "$env:systemroot\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit"

# Check if the directory exists
if (-not (Test-Path $directoryPath)) {
    # Create the directory if it doesn't exist
    New-Item -Path $directoryPath -ItemType Directory -Force
    Write-Host "Directory created: $directoryPath"
} else {
    Write-Host "Directory already exists: $directoryPath"
}

auditpol /backup /file:$temp_path\localpol.csv
(gc $temp_path\localpol.csv) -replace $hostname, '' | Out-File $temp_path\audit_pre.csv
$csvContent = gc $temp_path\audit_pre.csv
$modifiedContent = $csvContent[0]
$modifiedContent += ($csvContent[1..($csvContent.Count - 1)] | Where-Object { $_ -like '*System*' }) -join "`r`n"
$modifiedContent | Set-Content -Path $temp_path\audit.csv
# cp "$env:systemroot\system32\grouppolicy\machine\microsoft\windows nt\audit\audit.csv" "$env:systemroot\system32\grouppolicy\machine\microsoft\windows nt\audit\audit.csv.bak"
mv $temp_path\audit.csv "$env:systemroot\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv" -force

gpupdate /force
