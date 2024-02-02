#!/usr/bin/env bash
# This will only work on Ubuntu (it has not been tested on other distros)
set -e
export VER=8.12.0
export DNS=siemberry.home.arpa
# Replace the IP address with the one for your Kali-Purple instance
export ES_IP_ADDR=172.16.20.5

# Check if the DNS resolves to an IP address
if ! dig +short $DNS > /dev/null
then
  # If the DNS does not resolve, add it to the /etc/hosts file
  echo "$IP_ADDR $DNS" >> /etc/hosts
fi

# Make Elastic opt dir
mkdir /opt/elastic/

# Donwload all needed items
if type -P wget &> /dev/null; then
    wget $DNS:8000/apps/elastic-agent-$VER-linux-x86_64.tar.gz -P /opt/elastic/
    wget $DNS:8000/certs/ca.crt -P /opt/elastic/
    wget $DNS:8000/tokens/LAEtoken.txt -P /opt/elastic/
else
    curl $DNS:8000/apps/elastic-agent-$VER-linux-x86_64.tar.gz -o /opt/elastic/elastic-agent-$VER-linux-x86_64.tar.gz
    curl $DNS:8000/certs/ca.crt -o /opt/elastic/ca.crt
    curl $DNS:8000/tokens/LAEtoken.txt -o /opt/elastic/LAEtoken.txt
fi

# unpack the agent
tar xf /opt/elastic/elastic-agent-$VER-linux-x86_64.tar.gz -C /opt/elastic/

# make the cert dir
mkdir -p /etc/pki/fleet
cp /opt/elastic/ca.crt /etc/pki/fleet/ca.crt

# Check if Elasticsearch is reachable 
counter=0
kcheck=$(curl -L --silent --output /dev/null --cacert /opt/elastic/ca.crt -XGET "https://$DNS:9200" --write-out %{http_code})
until [ $kcheck -eq 401 ] || [ $counter -eq 12 ]
do
  echo "Checking if Elasticsearch is reachable, retrying..."
  sleep 5
  counter=$((counter+1))
  kcheck=$(curl -L --silent --output /dev/null --cacert /opt/elastic/ca.crt -XGET "https://$DNS:9200" --write-out %{http_code})
done

if [ $kcheck -eq 401 ]; then
  echo "Elasticsearch is reachable"
else
  echo "Elasticsearch is not reachable after 1 minute"
  exit 1
fi

# Install the agent
sudo /opt/elastic/elastic-agent-$VER-linux-x86_64/elastic-agent install -f \
  --url=https://$DNS:8220 \
  --enrollment-token=$(cat /opt/elastic/LAEtoken.txt) \
  --certificate-authorities=/opt/elastic/ca.crt