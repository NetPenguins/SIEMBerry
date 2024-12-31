#!/usr/bin/env bash
# This will only work on Ubuntu 20.04/23.10 on the Raspberry Pi 4 or Pi 5 (it has not been tested on other distros or platforms!)

# Exit script on error
set -e

# Test if the we can reach the internet to download packages
attempt=0
until curl --silent --head --fail https://www.google.com | grep -q "HTTP/.* 200"
do
    attempt=$((attempt+1))
    if [ $attempt -ge 5 ]; then
        echo "Device can't reach the internet on port 443 after 5 attempts. Exiting..."
        exit 1
    fi
    echo "offline, still waiting..."
    sleep 5
done
echo "online"

# Install Unzip, wget and jq
# Unzip is needed to unzip the Elastic Agent
# wget is needed to download everything
# jq is needed to parse the json (I used to use grep but jq is far better)
NEEDRESTART_MODE=a
apt update
apt install -y unzip wget jq tar gettext dnsutils

# Add Elastic and Kibana and the Elastic Agents
# Download and install Ealsticsearch and Kibana change ver to whatever you want
# For me 8.12.0 is the latest we put it in /apps dir to not download it again
# The -q flag is need to not spam stdout on the host machine (for when we build the config with Vagrant)
# We also pull the SHA512 hashes to verify the downloads

# var settings
export VER=8.17.0
# TO-DO Change this to the IP address of the Raspberry Pi
export IP_ADDR=172.16.20.5
export K_PORT=5601
export ES_PORT=9200
export F_PORT=8220
# Updated to "home.arpa" TLD for RFC 8375 compliance add it to your DNS server if you can
export DNS=siemberry.home.arpa
export SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# This override is only needed if you do not control your local DNS servers
# Check if the DNS resolves to an IP address
if ! dig +short $DNS > /dev/null
then
  # If the DNS does not resolve, add it to the /etc/hosts file
  echo "$IP_ADDR $DNS" >> /etc/hosts
fi

download_and_verify() {
  local url="$1"
  local dest_dir="$2"
  local file_name
  file_name=$(basename "$url")

  wget -nc -q "$url" -P "$dest_dir"
  wget -nc -q "${url}.sha512" -P "$dest_dir"

  pushd "$dest_dir" > /dev/null
  sha512sum -c "${file_name}.sha512" 2> /dev/null
  if [ $? -ne 0 ]; then
    echo "Checksum verification failed for ${file_name}"
    return 1
  else
    echo "Checksum verified for ${file_name}"
  fi
  popd > /dev/null
}

download_and_verify "https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-$VER-arm64.deb" "${SCRIPT_DIR}/apps"
download_and_verify "https://artifacts.elastic.co/downloads/kibana/kibana-$VER-arm64.deb" "${SCRIPT_DIR}/apps"
download_and_verify "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-$VER-linux-arm64.tar.gz" "${SCRIPT_DIR}/apps"
download_and_verify "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-$VER-linux-x86_64.tar.gz" "${SCRIPT_DIR}/apps"


# Make the config backup dir
mkdir /root/elasticbackup/

# We output to a temp password file allowing auto config later on
tar -xf ${SCRIPT_DIR}/apps/elastic-agent-$VER-linux-arm64.tar.gz -C /opt/
dpkg --install ${SCRIPT_DIR}/apps/elasticsearch-$VER-arm64.deb 2>&1 | tee /root/elasticbackup/ESUpass.txt
dpkg --install ${SCRIPT_DIR}/apps/kibana-$VER-arm64.deb

# Make the cert dir to prevent pop-up later
mkdir -p /tmp/elastic/certs/


# Config the instances file for cert gen the ip is $IP_ADDR
cat > /tmp/elastic/certs/instance.yml << EOF
instances:
  - name: 'elasticsearch'
    dns: ['$DNS']
    ip: ['$IP_ADDR']
  - name: 'kibana'
    dns: ['$DNS']
    ip: ['$IP_ADDR']
  - name: 'fleet'
    dns: ['$DNS']
    ip: ['$IP_ADDR']
EOF

# Make the certs and move them where they are needed
/usr/share/elasticsearch/bin/elasticsearch-certutil ca --pem --pass secret --out /tmp/elastic/certs/elastic-stack-ca.zip
unzip -q /tmp/elastic/certs/elastic-stack-ca.zip -d /tmp/elastic/certs/
/usr/share/elasticsearch/bin/elasticsearch-certutil cert --ca-cert /tmp/elastic/certs/ca/ca.crt -ca-key /tmp/elastic/certs/ca/ca.key --ca-pass secret --pem --in /tmp/elastic/certs/instance.yml --out /tmp/elastic/certs/certs.zip
unzip -q /tmp/elastic/certs/certs.zip -d /tmp/elastic/certs/

mkdir /etc/kibana/certs
mkdir /etc/pki/fleet

cp /tmp/elastic/certs/ca/ca.crt /tmp/elastic/certs/elasticsearch/* /etc/elasticsearch/certs
cp /tmp/elastic/certs/ca/ca.crt /tmp/elastic/certs/kibana/* /etc/kibana/certs
cp /tmp/elastic/certs/ca/ca.crt /tmp/elastic/certs/fleet/* /etc/pki/fleet
cp -r /tmp/elastic/certs/* /root/elasticbackup/

# This cp should be an unaliased cp to replace the ca.crt if it exists in the shared /certs dir
cp -u /tmp/elastic/certs/ca/ca.crt ${SCRIPT_DIR}/certs

# TO-DO change data path to where the external drive is mounted
# Config and start Elasticsearch (we are also increasing the timeout for systemd to 500)
mv /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml.bak

cat > /etc/elasticsearch/elasticsearch.yml << EOF
# ======================== Elasticsearch Configuration =========================
#
# ----------------------------------- Paths ------------------------------------
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
# ---------------------------------- Network -----------------------------------
network.host: $IP_ADDR
http.port: $ES_PORT
# --------------------------------- Discovery ----------------------------------
discovery.type: single-node
# ----------------------------------- X-Pack -----------------------------------
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.key: /etc/elasticsearch/certs/elasticsearch.key
xpack.security.transport.ssl.certificate: /etc/elasticsearch/certs/elasticsearch.crt
xpack.security.transport.ssl.certificate_authorities: [ "/etc/elasticsearch/certs/ca.crt" ]
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.key: /etc/elasticsearch/certs/elasticsearch.key
xpack.security.http.ssl.certificate: /etc/elasticsearch/certs/elasticsearch.crt
xpack.security.http.ssl.certificate_authorities: [ "/etc/elasticsearch/certs/ca.crt" ]
xpack.security.authc.api_key.enabled: true
EOF

sed -i 's/TimeoutStartSec=75/TimeoutStartSec=500/g' /lib/systemd/system/elasticsearch.service
systemctl daemon-reload
systemctl start elasticsearch
systemctl enable elasticsearch

# Gen the users and paste the output for later use
/usr/share/elasticsearch/bin/elasticsearch-reset-password -b -u kibana_system -a > /root/elasticbackup/Kibpass.txt

# Add the Kibana password to the keystore
grep "New value:" /root/elasticbackup/Kibpass.txt | awk '{print $3}' | sudo /usr/share/kibana/bin/kibana-keystore add --stdin elasticsearch.password

# Configure and start Kibana adding in the unique kibana_system keystore pass and generating the sec keys
cat > /etc/kibana/kibana.yml << EOF
# =========================== Kibana Configuration ============================
# -------------------------------- Network ------------------------------------
server.host: 0.0.0.0
server.port: $K_PORT
server.publicBaseUrl: "https://$DNS:$K_PORT"
# ------------------------------ Elasticsearch --------------------------------
elasticsearch.hosts: ["https://$IP_ADDR:$ES_PORT"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "\${elasticsearch.password}"
# ---------------------------------- Various -----------------------------------
telemetry.enabled: false
server.ssl.enabled: true
server.ssl.certificate: "/etc/kibana/certs/kibana.crt"
server.ssl.key: "/etc/kibana/certs/kibana.key"
elasticsearch.ssl.certificateAuthorities: [ "/etc/kibana/certs/ca.crt" ]
elasticsearch.ssl.verificationMode: "none"
# ---------------------------------- X-Pack ------------------------------------
xpack.security.encryptionKey: "$(tr -dc A-Za-z0-9 </dev/urandom | head -c 32 ; echo '')"
xpack.encryptedSavedObjects.encryptionKey: "$(tr -dc A-Za-z0-9 </dev/urandom | head -c 32 ; echo '')"
xpack.reporting.encryptionKey: "$(tr -dc A-Za-z0-9 </dev/urandom | head -c 32 ; echo '')"
EOF

systemctl start kibana
systemctl enable kibana

# Var settings (has to happen after Elastic is installed)
E_PASS=$(sudo grep "generated password for the elastic" /root/elasticbackup/ESUpass.txt | awk '{print $11}')

# Test if Kibana is running
echo "Testing if Kibana is online, could take some time, no more than 5 mins"
until curl --silent --cacert /tmp/elastic/certs/ca/ca.crt -XGET "https://$DNS:$K_PORT/api/fleet/agent_policies" -H 'accept: application/json' -u elastic:$E_PASS | grep -q '"items":\[\]'
do
    echo "Kibana starting, still waiting..."
    sleep 5
done
echo "Kibana online!"

# Install all the prebuilt rules
curl --silent -XPUT \
  --user elastic:$E_PASS \
  --cacert /tmp/elastic/certs/ca/ca.crt \
  --header @${SCRIPT_DIR}/config/headers.txt \
  --url "https://$DNS:$K_PORT/api/detection_engine/rules/prepackaged"

# Make the Fleet token
curl --silent -XPUT --url "https://$IP_ADDR:$ES_PORT/_security/service/elastic/fleet-server/credential/token/fleet-token-1" \
 --user elastic:$E_PASS \
 --output /root/elasticbackup/Ftoken.txt \
 --cacert /tmp/elastic/certs/ca/ca.crt

jq --raw-output '.token.value' /root/elasticbackup/Ftoken.txt > ${SCRIPT_DIR}/tokens/Ftoken.txt

# Add Fleet Policy
curl --silent -XPOST \
  --user  elastic:$E_PASS \
  --output /root/elasticbackup/FPid.txt \
  --cacert /tmp/elastic/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/agent_policies?sys_monitoring=true" \
  --header @${SCRIPT_DIR}/config/headers.txt \
  --data @${SCRIPT_DIR}/config/fleet_policy_add.json

jq --raw-output '.item.id' /root/elasticbackup/FPid.txt > ${SCRIPT_DIR}/keys/FPid.txt

export FLEET_POLICY_ID=$(cat ${SCRIPT_DIR}/keys/FPid.txt)

# Add Fleet Integration
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/elasticbackup/FIid.txt \
  --cacert /tmp/elastic/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/package_policies" \
  --header @${SCRIPT_DIR}/config/headers.txt \
  --data @<(envsubst < ${SCRIPT_DIR}/config/fleet_integration_add.json)

jq --raw-output '.item.id' /root/elasticbackup/FIid.txt > ${SCRIPT_DIR}/keys/FIid.txt

# Add host IP and yaml settings to Fleet API
curl --silent -XPUT \
 --user elastic:$E_PASS \
 --cacert /tmp/elastic/certs/ca/ca.crt \
 --url "https://$DNS:$K_PORT/api/fleet/package_policies/$(cat ${SCRIPT_DIR}/keys/FIid.txt)" \
 --header @${SCRIPT_DIR}/config/headers.txt \
 --data @<(envsubst < ${SCRIPT_DIR}/config/fleet_integration_update_ip.json)

# Add host IP and yaml settings to Fleet API
 curl --silent -XPUT \
 --user elastic:$E_PASS \
 --cacert /tmp/elastic/certs/ca/ca.crt \
 --url "https://$DNS:$K_PORT/api/fleet/outputs/fleet-default-output" \
 --header @${SCRIPT_DIR}/config/headers.txt \
 --data @<(envsubst < ${SCRIPT_DIR}/config/fleet_integration_update_es_ip.json)

# Create the Fleet Elastic Defender Intigration 
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/elasticbackup/FEDI.txt \
  --cacert /tmp/elastic/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/package_policies" \
  --header @<(envsubst < ${SCRIPT_DIR}/config/sec_headers.txt) \
  --data @<(envsubst < ${SCRIPT_DIR}/config/fleet_integration_defender_add.json)

jq --raw-output '.item.id' /root/elasticbackup/FEDI.txt > ${SCRIPT_DIR}/keys/FEDIid.txt

jq 'del(.item.id, .item.revision, .item.created_at, .item.created_by, .item.updated_at, .item.updated_by) | .item' /root/elasticbackup/FEDI.txt > /root/elasticbackup/FEDI_out.txt

jq '.inputs[0].config.policy.value.windows.malware.mode = "detect" |
.inputs[0].config.policy.value.mac.malware.mode = "detect" |
.inputs[0].config.policy.value.linux.malware.mode = "detect"' /root/elasticbackup/FEDI_out.txt > /root/elasticbackup/FEDI_in.txt

# Update the Fleet Elastic Defender Intigration to detect mode
curl --silent -XPUT \
  --user elastic:$E_PASS \
  --cacert /tmp/elastic/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/package_policies/$(cat ${SCRIPT_DIR}/keys/FEDIid.txt)" \
  --header @<(envsubst < ${SCRIPT_DIR}/config/sec_headers.txt) \
  --data @/root/elasticbackup/FEDI_in.txt

# Create the Windows Policy
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/elasticbackup/WPid.txt \
  --cacert /tmp/elastic/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/agent_policies?sys_monitoring=true" \
  --header @${SCRIPT_DIR}/config/headers.txt \
  --data @${SCRIPT_DIR}/config/windows_policy_add.json

jq --raw-output '.item.id' /root/elasticbackup/WPid.txt > ${SCRIPT_DIR}/keys/WPid.txt

export WINDOWS_POLICY_ID=$(cat ${SCRIPT_DIR}/keys/WPid.txt)

# Create the Linux Policy
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/elasticbackup/LPid.txt \
  --cacert /tmp/elastic/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/agent_policies?sys_monitoring=true" \
  --header @${SCRIPT_DIR}/config/headers.txt \
  --data @${SCRIPT_DIR}/config/linux_policy_add.json

jq --raw-output '.item.id' /root/elasticbackup/LPid.txt > ${SCRIPT_DIR}/keys/LPid.txt

export LINUX_POLICY_ID=$(cat ${SCRIPT_DIR}/keys/LPid.txt)

# Add Windows Integration
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/elasticbackup/WIid.txt \
  --cacert /tmp/elastic/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/package_policies" \
  --header @${SCRIPT_DIR}/config/headers.txt \
  --data @<(envsubst < ${SCRIPT_DIR}/config/windows_integration_add.json)

jq --raw-output '.item.id' /root/elasticbackup/WIid.txt > ${SCRIPT_DIR}/keys/WIid.txt

# Add Custom Windows Event Logs - Windows Defender Logs
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/elasticbackup/CWIid.txt \
  --cacert /tmp/elastic/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/package_policies" \
  --header @${SCRIPT_DIR}/config/headers.txt \
  --data @<(envsubst < ${SCRIPT_DIR}/config/windows_integration_update_defender_logs.json)

# Create the Windows Elastic Defender Intigration 
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/elasticbackup/WEDI.txt \
  --cacert /tmp/elastic/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/package_policies" \
  --header @<(envsubst < ${SCRIPT_DIR}/config/sec_headers.txt) \
  --data @<(envsubst < ${SCRIPT_DIR}/config/windows_integration_defender_add.json)

jq --raw-output '.item.id' /root/elasticbackup/WEDI.txt > ${SCRIPT_DIR}/keys/WEDIid.txt

jq 'del(.item.id, .item.revision, .item.created_at, .item.created_by, .item.updated_at, .item.updated_by) | .item' /root/elasticbackup/WEDI.txt > /root/elasticbackup/WEDI_out.txt

jq '.inputs[0].config.policy.value.windows.malware.mode = "detect" |
.inputs[0].config.policy.value.mac.malware.mode = "detect" |
.inputs[0].config.policy.value.linux.malware.mode = "detect"' /root/elasticbackup/WEDI_out.txt > /root/elasticbackup/WEDI_in.txt

# Update the Windows Elastic Defender Intigration to detect mode
curl --silent -XPUT \
  --user elastic:$E_PASS \
  --cacert /tmp/elastic/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/package_policies/$(cat ${SCRIPT_DIR}/keys/WEDIid.txt)" \
  --header @<(envsubst < ${SCRIPT_DIR}/config/sec_headers.txt) \
  --data @/root/elasticbackup/WEDI_in.txt

# Add Linux Auditd Integration
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/elasticbackup/LIid.txt \
  --cacert /tmp/elastic/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/package_policies" \
  --header @${SCRIPT_DIR}/config/headers.txt \
  --data @<(envsubst < ${SCRIPT_DIR}/config/linux_integration_auditd_add.json)

jq --raw-output '.item.id' /root/elasticbackup/LIid.txt > ${SCRIPT_DIR}/keys/LIid.txt

# Create the Linux Elastic Defender Intigration 
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/elasticbackup/LEDI.txt \
  --cacert /tmp/elastic/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/package_policies" \
  --header @<(envsubst < ${SCRIPT_DIR}/config/sec_headers.txt) \
  --data @<(envsubst < ${SCRIPT_DIR}/config/linux_integration_defender_add.json)

jq --raw-output '.item.id' /root/elasticbackup/LEDI.txt > ${SCRIPT_DIR}/keys/LEDIid.txt

jq 'del(.item.id, .item.revision, .item.created_at, .item.created_by, .item.updated_at, .item.updated_by) | .item' /root/elasticbackup/LEDI.txt > /root/elasticbackup/LEDI_out.txt

jq '.inputs[0].config.policy.value.windows.malware.mode = "detect" |
.inputs[0].config.policy.value.mac.malware.mode = "detect" |
.inputs[0].config.policy.value.linux.malware.mode = "detect"' /root/elasticbackup/LEDI_out.txt > /root/elasticbackup/LEDI_in.txt

# Update the Linux Elastic Defender Intigration to detect mode
curl --silent --user elastic:$E_PASS -XPUT "https://$DNS:$K_PORT/api/fleet/package_policies/$(cat ${SCRIPT_DIR}/keys/LEDIid.txt)" \
  --cacert /tmp/elastic/certs/ca/ca.crt \
  --header @<(envsubst < ${SCRIPT_DIR}/config/sec_headers.txt) \
  --data @/root/elasticbackup/LEDI_in.txt

# Enable all Windows and Linux default alerts (must have the pipe to dev null or it will spam STDOUT)
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --cacert /tmp/elastic/certs/ca/ca.crt \
  --header @${SCRIPT_DIR}/config/headers.txt \
  --url "https://$DNS:$K_PORT/api/detection_engine/rules/_bulk_action" \
  --data '{
  "query": "alert.attributes.tags: \"OS: Windows\" OR alert.attributes.tags: \"OS: Linux\"",
  "action": "enable"
}' > /dev/null

# Install the fleet server
sudo /opt/elastic-agent-$VER-linux-arm64/elastic-agent install -f --url=https://$DNS:$F_PORT \
 --fleet-server-es=https://$DNS:$ES_PORT \
 --fleet-server-service-token=$(cat ${SCRIPT_DIR}/tokens/Ftoken.txt) \
 --fleet-server-policy=$(cat ${SCRIPT_DIR}/keys/FPid.txt) \
 --certificate-authorities=${SCRIPT_DIR}/certs/ca.crt \
 --fleet-server-es-ca=/etc/pki/fleet/ca.crt \
 --fleet-server-cert=/etc/pki/fleet/fleet.crt \
 --fleet-server-cert-key=/etc/pki/fleet/fleet.key

# Get the Windows policy id
curl --silent --cacert /tmp/elastic/certs/ca/ca.crt -XGET "https://$DNS:$K_PORT/api/fleet/enrollment_api_keys" -H 'accept: application/json' -u elastic:$E_PASS | sed -e "s/\},{/'\n'/g" -e "s/items/'\n'/g" | grep -E -m1 $(cat ${SCRIPT_DIR}/keys/WPid.txt) | grep -oP '[a-zA-Z0-9\=]{40,}' > ${SCRIPT_DIR}/tokens/WAEtoken.txt
# Get the Linux policy id
curl --silent --cacert /tmp/elastic/certs/ca/ca.crt -XGET "https://$DNS:$K_PORT/api/fleet/enrollment_api_keys" -H 'accept: application/json' -u elastic:$E_PASS | sed -e "s/\},{/'\n'/g" -e "s/items/'\n'/g" | grep -E -m1 $(cat ${SCRIPT_DIR}/keys/LPid.txt) | grep -oP '[a-zA-Z0-9\=]{40,}' > ${SCRIPT_DIR}/tokens/LAEtoken.txt

# Cleanup
for file in "/root/elasticbackup/ESUpass.txt" "/root/elasticbackup/Kibpass.txt" "/root/elasticbackup/Ftoken.txt" "/root/elasticbackup/FPid.txt" "/root/elasticbackup/FIid.txt" "/root/elasticbackup/WPid.txt" "/root/elasticbackup/LPid.txt" "/root/elasticbackup/WIid.txt" "/root/elasticbackup/CWIid.txt" "/root/elasticbackup/WEDI.txt" "/root/elasticbackup/WEDI_out.txt" "/root/elasticbackup/WEDI_in.txt" "/root/elasticbackup/LIid.txt" "/root/elasticbackup/LEDI.txt" "/root/elasticbackup/LEDI_out.txt" "/root/elasticbackup/LEDI_in.txt" "/root/elasticbackup/FEDI.txt" "/root/elasticbackup/FEDI_in.txt" "/root/elasticbackup/FEDI_out.txt"
do
    sudo rm -f "$file"
done

echo "To log into KLibana go to https://$IP_ADDR:$K_PORT"
echo "Or go to https://$DNS:$K_PORT once you have updated your DNS settings in your hosts, hosts file!"
echo "Username: elastic"
echo "Password: $(echo $E_PASS)"
echo "SAVE THE PASSWORD!!!"
echo "If you didn't save this password you can reset the Elastic user password with this command"
echo "on the elastic host:"
echo "sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic"
echo "The CA cert is in certs/"
echo "Tokens are saved in tokens/"
echo "To enroll Windows agents use this token: $(cat ${SCRIPT_DIR}/tokens/WAEtoken.txt)"
echo "To enroll Linux agents use this token: $(cat ${SCRIPT_DIR}/tokens/LAEtoken.txt)"
