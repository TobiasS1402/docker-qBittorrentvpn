# qBittorrent and WireGuard
#
# Version 1.8

FROM ubuntu:20.04
MAINTAINER MarkusMcNugen

VOLUME /downloads
VOLUME /config

ENV DEBIAN_FRONTEND noninteractive

RUN usermod -u 99 nobody

# Update packages and install software
RUN apt-get update \
    && apt-get install -y --no-install-recommends apt-utils openssl \
    && apt-get install -y software-properties-common \
    && add-apt-repository ppa:qbittorrent-team/qbittorrent-stable \
    && apt-get update \
    && apt-get install -y qbittorrent-nox curl moreutils net-tools dos2unix kmod iptables ipcalc unrar jq wireguard openssl cron iproute2 \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Add configuration and scripts
ADD wireguard/ /etc/wireguard/
ADD qbittorrent/ /etc/qbittorrent/
ADD wireguard/ca.rsa.4096.crt /etc/ssl/certs

RUN chmod +x /etc/qbittorrent/*.sh /etc/qbittorrent/*.init /etc/wireguard/*.sh

RUN crontab -l | { cat; echo "*/15 * * * * bash /etc/wireguard/refresh_pia_port.sh 2>&1"; } | crontab -

# Expose ports and run
EXPOSE 8080
EXPOSE 8999
EXPOSE 8999/udp

CMD ["/bin/bash", "/etc/wireguard/start.sh"]