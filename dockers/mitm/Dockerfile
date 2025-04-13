FROM ubuntu:latest

# Install necessary system tools and dependencies, including Scapy
RUN apt update && apt install -y \
    tshark iproute2 iptables dnsmasq jq netmask bsdmainutils conntrack iputils-ping dnsutils \
    net-tools ethtool python3 python3-pip build-essential cmake libpcap-dev tcpdump vim \
    netcat-traditional curl ipcalc libnats-dev scapy

# Disable IP forwarding; our switch code will handle it!
RUN echo 'net.ipv4.ip_forward=0' >> /etc/sysctl.conf && sysctl -p

# Set the working directory
WORKDIR /code/mitm/switch
