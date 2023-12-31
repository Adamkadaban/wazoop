#!/bin/bash

# Based on these guides: https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/index.html

if [ "$(id -u)" != "0" ]; then
    echo "You must be root to run this script."
    exit 1
fi

echo "If running with 4gb ram, this will take ~5-10 minutes"
echo "If running with insufficient resources... good luck"
echo ""

echo "##########################################"
echo "#           Installing Indexer           #"
echo "##########################################"

cd /root
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml

sed -i 's/<indexer-node-ip>/127.0.0.1/g' config.yml
sed -i 's/<wazuh-manager-ip>/127.0.0.1/g' config.yml
sed -i 's/<dashboard-node-ip>/127.0.0.1/g' config.yml

bash wazuh-install.sh --generate-config-files -i
bash wazuh-install.sh --wazuh-indexer node-1 -i -o
bash wazuh-install.sh --start-cluster -i


echo "##########################################"
echo "#            Installing Server           #"
echo "##########################################"

bash wazuh-install.sh --wazuh-server wazuh-1 -i -o

echo "##########################################"
echo "#          Installing Dashboard          #"
echo "##########################################"

bash wazuh-install.sh --wazuh-dashboard dashboard -i -o
tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
