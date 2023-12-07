$WAZUH_MGR = ""

Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi -OutFile ${env.tmp}\wazuh-agent

msiexec.exe /i ${env.tmp}\wazuh-agent /q WAZUH_MANAGER="$WAZUH_MGR" WAZUH_AGENT_NAME='Windows' WAZUH_REGISTRATION_SERVER="$WAZUH_MGR"

net start WazuhSvc
