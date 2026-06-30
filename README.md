# CodeAlpha — Task 1: Basic Network Sniffer

**Intern:** Uswa Fatima  
**Internship:** CodeAlpha Cybersecurity Internship  
**Tool Used:** Python 3 + Scapy  

## About

A Python-based network packet sniffer that captures live traffic and analyzes:
- Source and Destination IP addresses
- Protocol identification (TCP, UDP, ICMP, ARP)
- Port numbers and TCP flags
- DNS queries
- HTTP / HTTPS / SSH detection
- Raw payload preview
- Saves full capture log to file

## Requirements

sudo apt install python3-scapy -y

## Usage

sudo python3 network_sniffer.py
sudo python3 network_sniffer.py -i eth0
sudo python3 network_sniffer.py -c 100 -f "tcp"
sudo python3 network_sniffer.py -f "port 80"
sudo python3 network_sniffer.py -f "udp port 53"
sudo python3 network_sniffer.py -c 0

## Legal Notice

This tool is for educational purposes only. Only use on networks you own or have explicit permission to monitor.
