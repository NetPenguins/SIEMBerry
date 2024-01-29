# SIEMBerry 
Run the Elastic Stack on a Raspberry Pi.  
## Note  
This has been tested for Elastic 8.12.0 on Ubuntu 20.04/23.10 on the Raspberry Pi 4B and Pi 5 YMMV with other distros and platforms.

**This is not for production!**  
Please I don't want to be complicit in an `rm -rf /` of prod on a Monday morning/Friday afternoon at 17:30, thank you.  

## Instructions  
Use `get clone` to download this script  
Review the contents of the newly downloaded `ESBootstrap.sh` script  
Install with `sudo bash ESBootstrap.sh`  
Take note of the password and tokens at the end!  
If you didn't save this password you can reset the Elastic user password with this command
on the Pi:  
`sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic`  
To access your new SIEM go to https://siemberry.home.arpa:5601 once you have run the installer script and added the DNS record to your DNS servers or hosts, host file.   Ignore the certificate warning we are using self-signed certs by design.  
I would advise you also use an external drive, how Elasticsearch writes to disk may not be ideal for an SD card.  

## Explanation
The script installs Elasticsearch, Kibana, and Fleet in a "non-development" mode (main security settings like TLS, and Kibana sec keys, etc are enabled) on a Raspberry Pi so you can install Elastic Agents around your network and manage them centrally with Fleet or collet logs from OPNsense/pfSense.

### Downloads
The download_and_verify bash function downloads all the required applications at the specified version and checks the SHA-512 hashes automatically.  

### Certificates
We make use of the Elasticsearch certutil built in to generate certificates for Elasticsearch, Kibana and Fleet. The Fleet certificates are needed for it to be setup in a manageable state. The certs are then moved to where they are needed in each apps /etc/ dir (Except Fleet where we make a place for them in /etc/pki/fleet/). The root CA cert is placed in ./certs for ease of access, no file-level permissions are taken into account!  

### Elasticsearch
A single node setup is all we need for our purposes. All certificate paths are then provisioned. The Systemd timeout is also changed from the default 75 seconds to ~8 minutes, this is to account for the fact that there may be CPU prioritization challenges as we are in a smaller system. The service is then started and enabled (needed to account for restarts). You can check the status with `sudo systemctl status elasticsearch`. We use the `elastic` user/pass for API authentications, I am planning to change this to an API user in the future. The authentication mechanism in place at the moment means we save the Elastic super users password to a variable (not ideal). To start Elasticsearch if it ever doesn't on reboot use `sudo systemctl start elasticsearch`.

### Kibana
We are using password based authentication between Kibana and ElasticSearch so the password is created and later added to the Kibana key store (Not to store it in plain text in the .yml file). The Kibana configuration .yml sets all required values `server.publicUrl` is set to prevent a popup, and the `xpack.*encryptionKey` are set to use as encryption keys for different parts of the Kibana platform. The service is then started and enabled. You can check the status with `sudo systemctl status kibana`. To start Kibana if it ever doesn't on reboot use `sudo systemctl start kibana`.

### Fleet
Most of the `curl` calls are related to Fleet. We setup the Fleet token for enrollment, then create the policy, then add the integration. Once the policy is in place we update the settings as required. You will notice I am using `curl`'s `@` operator, this is to read the unchanging sections like the headers and body from files, so we only need to change them once. All required keys (I call them keys but they're the value section of the key:value JSON pairs) are placed in ./keys. `jq` is used to replace my old `grep` methods to extract and modify all required values.  

#### Fleet Policies
Some background Fleet Policies house the integrations we enable, I've separated this deployment into three main sections; 
- Fleet (Used to be a default policy but now we need to create it)  
- Windows  
- Linux  

This separation allows for targeted integrations to apply to only one major platform at a time, this can be subdivided further so a "Linux - Apache", "Linux - SQLite", "Windows - IIS" etc. but for our purposes this division allows enough segregation.  
#### Fleet Integrations
The integrations we enable are as follows;  

**Fleet**  
- Fleet Server, needed to be a Fleet Server.  
- System, used to get metrics about the host system.  
- Fleet Elastic Defender integration, used to protect the Fleet server. For our testing purposes the Defender integration is enabled in "detect" mode, to change this on windows change these [lines](https://github.com/ScioShield/SIEMBerry/blob/bd0e227435356737592e07801b43fa69cf2cb859/ESBootstrap.sh#L269) to "protect".  

**Windows**  
- Windows integration, this is used to gather logs from the Windows hosts, like the event viewer logs.  
- Windows integration custom, this is used to get the custom logs produced by Windows Defender.  
- Windows Elastic Defender integration, the Elastic Defender is cross platform, but I've decided to instead to enable each major platform to have it's own Elastic Defender instance. For our testing purposes the Defender integration is enabled in "detect" mode, to change this on windows change these [lines](https://github.com/ScioShield/SIEMBerry/blob/bd0e227435356737592e07801b43fa69cf2cb859/ESBootstrap.sh#L340) to "protect".  
- Windows System integration, this is provisioned by default for all policies, it gathers system metrics like CPU & RAM usage.  

**Linux**  
- Linux integration, like the Windows integration this allows for logs from Linux to be gathered.  
- Linux Elastic Defender integration, like the Windows counter part this enables the Elastic Defender in detect mode. To change the integration from "detect" to "protect" mode change these [lines](https://github.com/ScioShield/SIEMBerry/blob/bd0e227435356737592e07801b43fa69cf2cb859/ESBootstrap.sh#L376) to "protect".  
- Linux system integration, this is provisioned by default for all policies, it gathers system metrics like CPU & RAM usage.  

### Alerts
We automatically enable all alerts for the Windows and Linux platforms (or at least if they are tagged with either platform) in this [line](https://github.com/ScioShield/SIEMBerry/blob/bd0e227435356737592e07801b43fa69cf2cb859/ESBootstrap.sh#L393). If there are any more tags you'd like enabled add an `OR alert.attributes.tags: \"CHANGEME\"` to the end of the query section.

#### Fleet Server
The fleet server is then enabled by installing the Elastic Agent with specific settings.

#### Enrollment Tokens
We place them in the ./tokens dir and print them. You will also need the CA cert located in the ./certs/ dir to enroll new agents. Here is an example for Windows(TBD) here is an example for [Linux](https://github.com/ScioShield/SIEMBerry/blob/bd0e227435356737592e07801b43fa69cf2cb859/LinuxAgentInstaller.sh#L38).  


## DNS settings  
Replace SIEMBerry_IP with the IP of the Pi if you don't roll your own DNS servers  
### Windows Powershell  
`Add-Content 'C:\Windows\System32\Drivers\etc\hosts' "SIEMBerry_IP siemberry.home.arpa"`  
### Linux Bash  
`sudo echo "SIEMBerry_IP siemberry.home.arpa" >> /etc/hosts`  

## Improvements  
- Think about adding the Elasticsearch integration to the Fleet policy as default  
- Add Windows installer script (with DNS resolver check) and download the Agent  
- Add a solutions considered section (why isn't this using SecurityOnion, etc)  
- Think about Caddy  
- Think about Ansible  
- Think about having an installer and a running config updater  
- Raise a discuss post regarding why the Agent doesn't work properly on Arm / Raspberry Pis  