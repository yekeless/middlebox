FROM ubuntu:latest

# Install necessary system tools and dependencies, including Scapy
RUN apt update && apt install -y \
    tshark jq iputils-ping dnsutils net-tools iperf tcpdump netcat-traditional curl \
    iproute2 ethtool iptables nftables python3 python3-pip build-essential cmake libpcap-dev vim \
    scapy

# Enable IPv4 forwarding
RUN echo 'net.ipv4.ip_forward=0' >> /etc/sysctl.conf && sysctl -p

# Set the working directory
WORKDIR /code/sec