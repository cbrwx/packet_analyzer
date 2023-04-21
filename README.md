# packet_analyzer
This packet analyzer is a Python script that uses Scapy to monitor network traffic and analyze packets in real-time or from a pcap file. It detects and logs suspicious activities, such as connections from suspicious IP addresses, watchlist countries, and the presence of specific keywords or domains in the packet payload.

# Features
- Analyzes network packets in real-time or from a pcap file
- Detects and logs suspicious activities based on:
- Predefined keywords in the packet payload
- Known suspicious IP addresses and domains
- Watchlist countries
- Supports multiple transport layer protocols: TCP, UDP, ICMP, and SCTP
- Identifies application layer protocols: HTTP, HTTPS, FTP Data, FTP Control, and DNS
- Logs packet information to a file (packet_log.txt) for further analysis
# Requirements
- Python 3.x
- Scapy
- tldextract
- Requests
# Usage
To run the script:

- For analyzing a pcap file: python script.py -f captured_packets.pcap
- For capturing packets in real-time: python script.py
# Customization
You can customize the list of keywords, suspicious IPs, domains, and watchlist countries by modifying the following variables:

- keywords: A list of keywords to search for in the packet payload
- suspicious_ips: A list of known suspicious IP addresses
- suspicious_domains: A list of known suspicious domains
- watchlist_countries: A list of countries to watch for suspicious activity
# License
This project is licensed under the MIT License.

.cbrwx
