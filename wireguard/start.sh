#!/usr/local/bin/bash

# Copyright (C) 2020 Private Internet Access, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Only allow script to run as root

now="$(date)"

echo "
################################
    run_setup.sh
################################
Starting script at $now
"

if [ "$(whoami)" != "root" ]; then
  echo "This script needs to be run as root. Try again with 'sudo $0'"
  exit 1
fi

# Hardcoding all the settings to make testing (and using!) easier

# Fetching credentials from local pass.txt file
# just so they don't show on github
# Username on first line, password on second

protocol="udp"
encryption="strong"

# To use openvn remove # from start of that line and add it to start of "PIA_AUTOCONNECT=wireguard"
#PIA_AUTOCONNECT="openvpn_${protocol}_${encryption}"
PIA_AUTOCONNECT=wireguard
export PIA_AUTOCONNECT

PIA_DNS="false"
export PIA_DNS
PIA_PF="false"
export PIA_PF
MAX_LATENCY=0.1
export MAX_LATENCY

#!/usr/local/bin/bash
# Copyright (C) 2020 Private Internet Access, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

echo "
################################
    get_region_and_token.sh
################################
"

# This function allows you to check if the required tools have been installed.
function check_tool() {
  cmd=$1
  package=$2
  if ! command -v $cmd &>/dev/null
  then
    echo "$cmd could not be found"
    echo "Please install $package"
    exit 1
  fi
}
# Now we call the function to make sure we can use curl and jq.
check_tool curl curl
check_tool jq jq

# This allows you to set the maximum allowed latency in seconds.
# All servers that respond slower than this will be ignored.
# You can inject this with the environment variable MAX_LATENCY.
# The default value is 50 milliseconds.
MAX_LATENCY=${MAX_LATENCY:-0.05}
export MAX_LATENCY

serverlist_url='https://serverlist.piaservers.net/vpninfo/servers/v4'

# This function checks the latency you have to a specific region.
# It will print a human-readable message to stderr,
# and it will print the variables to stdout
printServerLatency() {
  serverIP="$1"
  regionID="$2"
  regionName="$(echo ${@:3} |
    sed 's/ false//' | sed 's/true/(geo)/')"
  time=$(LC_NUMERIC=en_US.utf8 curl -o /dev/null -s \
    --connect-timeout $MAX_LATENCY \
    --write-out "%{time_connect}" \
    http://$serverIP:443)
  if [ $? -eq 0 ]; then
    >&2 echo Got latency ${time}s for region: $regionName
    echo $time $regionID $serverIP
  fi
}
export -f printServerLatency

echo -n "Getting the server list... "
# Get all region data since we will need this on multiple occasions
all_region_data=$(curl -s "$serverlist_url" | head -1)

# If the server list has less than 1000 characters, it means curl failed.
if [[ ${#all_region_data} -lt 1000 ]]; then
  echo "Could not get correct region data. To debug this, run:"
  echo "$ curl -v $serverlist_url"
  echo "If it works, you will get a huge JSON as a response."
  exit 1
fi
# Notify the user that we got the server list.
echo "OK!"

# Test one server from each region to get the closest region.
# If port forwarding is enabled, filter out regions that don't support it.
if [[ $PIA_PF == "true" ]]; then
  echo Port Forwarding is enabled, so regions that do not support
  echo port forwarding will get filtered out.
  summarized_region_data="$( echo $all_region_data |
    jq -r '.regions[] | select(.port_forward==true) |
    .servers.meta[0].ip+" "+.id+" "+.name+" "+(.geo|tostring)' )"
else
  summarized_region_data="$( echo $all_region_data |
    jq -r '.regions[] |
    .servers.meta[0].ip+" "+.id+" "+.name+" "+(.geo|tostring)' )"
fi
echo Testing regions that respond \
  faster than $MAX_LATENCY seconds:
bestRegion="$(echo "$summarized_region_data" |
  xargs -I{} bash -c 'printServerLatency {}' |
  sort | head -1 | awk '{ print $2 }')"

if [ -z "$bestRegion" ]; then
  echo ...
  echo No region responded within ${MAX_LATENCY}s, consider using a higher timeout.
  echo For example, to wait 1 second for each region, inject MAX_LATENCY=1 like this:
  echo $ MAX_LATENCY=1 ./get_region_and_token.sh
  exit 1
fi

# Get all data for the best region
regionData="$( echo $all_region_data |
  jq --arg REGION_ID "$bestRegion" -r \
  '.regions[] | select(.id==$REGION_ID)')"

echo -n The closest region is "$(echo $regionData | jq -r '.name')"
if echo $regionData | jq -r '.geo' | grep true > /dev/null; then
  echo " (geolocated region)."
else
  echo "."
fi
echo
bestServer_meta_IP="$(echo $regionData | jq -r '.servers.meta[0].ip')"
bestServer_meta_hostname="$(echo $regionData | jq -r '.servers.meta[0].cn')"
bestServer_WG_IP="$(echo $regionData | jq -r '.servers.wg[0].ip')"
bestServer_WG_hostname="$(echo $regionData | jq -r '.servers.wg[0].cn')"
bestServer_OT_IP="$(echo $regionData | jq -r '.servers.ovpntcp[0].ip')"
bestServer_OT_hostname="$(echo $regionData | jq -r '.servers.ovpntcp[0].cn')"
bestServer_OU_IP="$(echo $regionData | jq -r '.servers.ovpnudp[0].ip')"
bestServer_OU_hostname="$(echo $regionData | jq -r '.servers.ovpnudp[0].cn')"

echo "The script found the best servers from the region closest to you.
When connecting to an IP (no matter which protocol), please verify
the SSL/TLS certificate actually contains the hostname so that you
are sure you are connecting to a secure server, validated by the
PIA authority. Please find bellow the list of best IPs and matching
hostnames for each protocol:
Meta Services: $bestServer_meta_IP // $bestServer_meta_hostname
WireGuard: $bestServer_WG_IP // $bestServer_WG_hostname
OpenVPN TCP: $bestServer_OT_IP // $bestServer_OT_hostname
OpenVPN UDP: $bestServer_OU_IP // $bestServer_OU_hostname
"

if [[ ! $PIA_USER || ! $PIA_PASS ]]; then
  echo If you want this script to automatically get a token from the Meta
  echo service, please add the variables PIA_USER and PIA_PASS. Example:
  echo $ PIA_USER=p0123456 PIA_PASS=xxx ./get_region_and_token.sh
  exit 1
fi

echo "The ./get_region_and_token.sh script got started with PIA_USER and PIA_PASS,
so we will also use a meta service to get a new VPN token."

echo "Trying to get a new token by authenticating with the meta service..."
generateTokenResponse=$(curl -s -u "$PIA_USER:$PIA_PASS" \
  --connect-to "$bestServer_meta_hostname::$bestServer_meta_IP:" \
  --cacert "/etc/ssl/certs/ca.rsa.4096.crt" \
  "https://$bestServer_meta_hostname/authv3/generateToken")
echo "$generateTokenResponse"

if [ "$(echo "$generateTokenResponse" | jq -r '.status')" != "OK" ]; then
  echo "Could not get a token. Please check your account credentials."
  echo
  echo "You can also try debugging by manually running the curl command:"
  echo $ curl -vs -u "$PIA_USER:$PIA_PASS" --cacert ca.rsa.4096.crt \
    --connect-to "$bestServer_meta_hostname::$bestServer_meta_IP:" \
    https://$bestServer_meta_hostname/authv3/generateToken
  exit 1
fi

token="$(echo "$generateTokenResponse" | jq -r '.token')"
echo "This token will expire in 24 hours.
"

# just making sure this variable doesn't contain some strange string
if [ "$PIA_PF" != true ]; then
  PIA_PF="false"
fi


echo The ./get_region_and_token.sh script got started with
echo PIA_AUTOCONNECT=wireguard, so we will automatically connect to WireGuard,
echo by running this command:
echo $ PIA_TOKEN=\"$token\" \\
echo WG_SERVER_IP=$bestServer_WG_IP WG_HOSTNAME=$bestServer_WG_hostname \\
echo PIA_PF=$PIA_PF ./connect_to_wireguard_with_token.sh
echo PIA_PF=$PIA_PF PIA_TOKEN="$token" WG_SERVER_IP=$bestServer_WG_IP WG_HOSTNAME=$bestServer_WG_hostname
PIA_PF=$PIA_PF
PIA_TOKEN="$token"
WG_SERVER_IP=$bestServer_WG_IP
WG_HOSTNAME=$bestServer_WG_hostname

#!/usr/local/bin/bash
# Copyright (C) 2020 Private Internet Access, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# This script has not been completely edited to make it 
# BSD-compatible because I don't use wireguard.  

# This function allows you to check if the required tools have been installed.
function check_tool() {
  cmd=$1
  package=$2
  if ! command -v $cmd &>/dev/null
  then
    echo "$cmd could not be found"
    echo "Please install $package"
    exit 1
  fi
}
# Now we call the function to make sure we can use wg-quick, curl and jq.
check_tool wg-quick wireguard-tools
check_tool curl curl
check_tool jq jq

# PIA currently does not support IPv6. In order to be sure your VPN
# connection does not leak, it is best to disabled IPv6 altogether.

<< 'MULTILINE-COMMENT'
( This doesn't work on FreeBSD. IPv6 is instead disabled in 
  openvpn_config/standard.ovpn and strong.ovpn )
if [ $(sysctl -n net.ipv6.conf.all.disable_ipv6) -ne 1 ] ||
  [ $(sysctl -n net.ipv6.conf.default.disable_ipv6) -ne 1 ]
then
  echo 'You should consider disabling IPv6 by running:'
  echo 'sysctl -w net.ipv6.conf.all.disable_ipv6=1'
  echo 'sysctl -w net.ipv6.conf.default.disable_ipv6=1'
fi
MULTILINE-COMMENT

# Create ephemeral wireguard keys, that we don't need to save to disk.
privKey="$(wg genkey)"
export privKey
pubKey="$( echo "$privKey" | wg pubkey)"
export pubKey

# Authenticate via the PIA WireGuard RESTful API.
# This will return a JSON with data required for authentication.
# The certificate is required to verify the identity of the VPN server.
# In case you didn't clone the entire repo, get the certificate from:
# https://github.com/pia-foss/manual-connections/blob/master/ca.rsa.4096.crt
# In case you want to troubleshoot the script, replace -s with -v.
echo Trying to connect to the PIA WireGuard API on $WG_SERVER_IP...
wireguard_json="$(curl -s -G \
  --connect-to "$WG_HOSTNAME::$WG_SERVER_IP:" \
  --cacert "/etc/ssl/certs/ca.rsa.4096.crt" \
  --data-urlencode "pt=${PIA_TOKEN}" \
  --data-urlencode "pubkey=$pubKey" \
  "https://${WG_HOSTNAME}:1337/addKey" )"
export wireguard_json
echo "$wireguard_json"

# Check if the API returned OK and stop this script if it didn't.
if [ "$(echo "$wireguard_json" | jq -r '.status')" != "OK" ]; then
  >&2 echo "Server did not return OK. Stopping now."
  exit 1
fi

# Multi-hop is out of the scope of this repo, but you should be able to
# get multi-hop running with both WireGuard and OpenVPN by playing with
# these scripts. Feel free to fork the project and test it out.
echo
echo Trying to disable a PIA WG connection in case it exists...
wg-quick down pia && echo Disconnected!
echo

# Create the WireGuard config based on the JSON received from the API
# In case you want this section to also add the DNS setting, please
# start the script with PIA_DNS=true.
# This uses a PersistentKeepalive of 25 seconds to keep the NAT active
# on firewalls. You can remove that line if your network does not
# require it.
echo -n "Trying to write /etc/wireguard/pia.conf... "
mkdir -p /etc/wireguard
if [ "$PIA_DNS" == true ]; then
  dnsServer="$(echo "$wireguard_json" | jq -r '.dns_servers[0]')"
  echo Trying to set up DNS to $dnsServer. In case you do not have resolvconf,
  echo this operation will fail and you will not get a VPN. If you have issues,
  echo start this script without PIA_DNS.
  dnsSettingForVPN="DNS = $dnsServer"
fi
echo "
[Interface]
Address = $(echo "$wireguard_json" | jq -r '.peer_ip')
PrivateKey = $privKey
$dnsSettingForVPN
[Peer]
PersistentKeepalive = 25
PublicKey = $(echo "$wireguard_json" | jq -r '.server_key')
AllowedIPs = 0.0.0.0/0
Endpoint = ${WG_SERVER_IP}:$(echo "$wireguard_json" | jq -r '.server_port')
" > /etc/wireguard/pia.conf || exit 1
echo OK!

# Start the WireGuard interface.
# If something failed, stop this script.
# If you get DNS errors because you miss some packages,
# just hardcode /etc/resolv.conf to "nameserver 10.0.0.242".
echo
echo Trying to create the wireguard interface...
wg-quick up pia || exit 1
echo "The WireGuard interface got created.
At this point, internet should work via VPN.

--> to disconnect the VPN, run:
$ wg-quick down pia"

# This section will stop the script if PIA_PF is not set to "true".
echo -n "
#This script got started with PIA_PF=true. We will allow WireGuard to fully
#initialize and after that we will try to enable PF by running the following
#command:
#$ PIA_TOKEN=$PIA_TOKEN \\
#  PF_GATEWAY=\"$(echo "$wireguard_json" | jq -r '.server_vip')\" \\
#  PF_HOSTNAME=\"$WG_HOSTNAME\" \\
#  ./port_forwarding.sh
  
Starting PF in "
for i in {5..1}; do
  echo -n "$i... "
  sleep 1
done
echo
echo

PIA_TOKEN=$PIA_TOKEN \
  PF_GATEWAY="$(echo "$wireguard_json" | jq -r '.server_vip')" \
export PF_GATEWAY
  PF_HOSTNAME="$WG_HOSTNAME" \
export PF_HOSTNAME

#!/usr/local/bin/bash
# Copyright (C) 2020 Private Internet Access, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

echo "
#######################################
    port_forwarding.sh
#######################################
"

# This function allows you to check if the required tools have been installed.
function check_tool() {
  cmd=$1
  package=$2
  if ! command -v $cmd &>/dev/null
  then
    echo "$cmd could not be found"
    echo "Please run 'pkg install $package'"
    exit 1
  fi
}
# Now we call the function to make sure we can use base64.
check_tool base64 base64

echo "PF_HOSTNAME $PF_HOSTNAME"
echo "PF_GATEWAY $PF_GATEWAY"
echo "PIA_TOKEN $PIA_TOKEN"

# Check if the mandatory environment variables are set.
if [[ ! $PF_GATEWAY || ! $PIA_TOKEN || ! $PF_HOSTNAME ]]; then
  echo This script requires 3 env vars:
  echo PF_GATEWAY  - the IP of your gateway
  echo PF_HOSTNAME - name of the host used for SSL/TLS certificate verification
  echo PIA_TOKEN   - the token you use to connect to the vpn services
  echo
  echo An easy solution is to just run get_region_and_token.sh
  echo as it will guide you through getting the best server and
  echo also a token. Detailed information can be found here:
  echo https://github.com/pia-foss/manual-connections
exit 1
fi

# The port forwarding system has required two variables:
# PAYLOAD: contains the token, the port and the expiration date
# SIGNATURE: certifies the payload originates from the PIA network.

# Basically PAYLOAD+SIGNATURE=PORT. You can use the same PORT on all servers.
# The system has been designed to be completely decentralized, so that your
# privacy is protected even if you want to host services on your systems.

# You can get your PAYLOAD+SIGNATURE with a simple curl request to any VPN
# gateway, no matter what protocol you are using. Considering WireGuard has
# already been automated in this repo, here is a command to help you get
# your gateway if you have an active OpenVPN connection:
# $ ip route | head -1 | grep tun | awk '{ print $3 }'
# This section will get updated as soon as we created the OpenVPN script.

# Get the payload and the signature from the PF API. This will grant you
# access to a random port, which you can activate on any server you connect to.
# If you already have a signature, and you would like to re-use that port,
# save the payload_and_signature received from your previous request
# in the env var PAYLOAD_AND_SIGNATURE, and that will be used instead.
if [[ ! $PAYLOAD_AND_SIGNATURE ]]; then
  echo "Getting new signature..."
  payload_and_signature="$(curl -s -m 5 \
    --connect-to "$PF_HOSTNAME::$PF_GATEWAY:" \
    --cacert "/etc/ssl/certs/ca.rsa.4096.crt" \
    -G --data-urlencode "token=${PIA_TOKEN}" \
    "https://${PF_HOSTNAME}:19999/getSignature")"
else
  payload_and_signature="$PAYLOAD_AND_SIGNATURE"
  echo "Using the following payload_and_signature from the env var:"
fi
echo "Payload and signature are: $payload_and_signature"
export payload_and_signature

# Check if the payload and the signature are OK.
# If they are not OK, just stop the script.
if [ "$(echo "$payload_and_signature" | jq -r '.status')" != "OK" ]; then
  echo "The payload_and_signature variable does not contain an OK status."
  exit 1
fi

# We need to get the signature out of the previous response.
# The signature will allow the us to bind the port on the server.
signature="$(echo "$payload_and_signature" | jq -r '.signature')"

# The payload has a base64 format. We need to extract it from the
# previous response and also get the following information out:
# - port: This is the port you got access to
# - expires_at: this is the date+time when the port expires
payload="$(echo "$payload_and_signature" | jq -r '.payload')"
port="$(echo "$payload" | base64 -d | jq -r '.port')"

# The port normally expires after 2 months. If you consider
# 2 months is not enough for your setup, please open a ticket.
expires_at="$(echo "$payload" | base64 -d | jq -r '.expires_at')"

# Display some information on the screen for the user.
echo "The signature is OK.
--> The port is $port and it will expire on $expires_at. <--
"

# Save variables to files so refresh script can get them
pf_filepath=/pia-info/pf
mkdir $pf_filepath
echo "$PF_HOSTNAME" > $pf_filepath/PF_HOSTNAME
echo "$PF_GATEWAY" > $pf_filepath/PF_GATEWAY
echo "$payload" > $pf_filepath/payload
echo "$signature" > $pf_filepath/signature
echo "$port" > $pf_filepath/port
echo "$expires_at" > $pf_filepath/expires_at

# Final script will bind/refresh the port.  Run it with
# cron every 15 minutes so PIA doesn't delete port
# forwarding.  However it will still expire in 2 months.
exec /bin/bash /etc/qbittorrent/iptables.sh

