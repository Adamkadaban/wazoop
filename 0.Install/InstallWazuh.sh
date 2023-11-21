#!/bin/bash

# Based on these guides: https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/index.html

if [ "$(id -u)" != "0" ]; then
    echo "You must be root to run this script."
    exit 1
fi

echo "##########################################"
echo "#          Installing Indexer            #"
echo "##########################################"

cd /root
curl -sO https://packages.wazuh.com/4.6/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.6/config.yml

sed -i 's/<indexer-node-ip>/127.0.0.1/g' config.yml
sed -i 's/<wazuh-manager-ip>/127.0.0.1/g' config.yml
sed -i 's/<dashboard-node-ip>/127.0.0.1/g' config.yml

bash wazuh-install.sh --generate-config-files
bash wazuh-install.sh --wazuh-indexer node-1
bash wazuh-install.sh --start-cluster

