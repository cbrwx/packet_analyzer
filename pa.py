import argparse
from scapy.all import *
import datetime
import re
import requests
import json
import tldextract
import logging
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.sctp import SCTP
from scapy.layers.http import HTTPRequest, HTTPResponse

# Configure the logging system
logging.basicConfig(
    filename="packet_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Define keywords or patterns to search for in the payload
keywords = ["suspicious", "keyword1", "keyword2"]
pattern = re.compile("|".join(keywords))

# List of known suspicious IP addresses and domains
suspicious_ips = ["192.0.2.1", "198.51.100.2", "203.0.113.3"]
suspicious_domains = ["suspicious-domain.com", "malicious-site.org"]

# List of countries to watch for suspicious activity
watchlist_countries = ["Russia1", "Russia2"] # Ukraine<3

def get_transport_layer(packet):
    if TCP in packet:
        return 'TCP', packet[TCP]
    elif UDP in packet:
        return 'UDP', packet[UDP]
    elif ICMP in packet:
        return 'ICMP', packet[ICMP]
    elif SCTP in packet:
        return 'SCTP', packet[SCTP]
    else:
        return 'Other', None

def detect_keywords(payload):
    matches = pattern.findall(payload)
    return matches

def is_suspicious_ip(ip):
    return ip in suspicious_ips

def get_country(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        return data.get("country")
    except:
        return None

def is_watchlist_country(country):
    return country in watchlist_countries

def extract_domain(payload):
    return tldextract.extract(payload).domain

def is_suspicious_domain(domain):
    return domain in suspicious_domains

def get_app_layer_protocol(src_port, dst_port):
    app_ports = {
        80: "HTTP",
        443: "HTTPS",
        20: "FTP Data",
        21: "FTP Control",
        53: "DNS",
    }
    return app_ports.get(src_port) or app_ports.get(dst_port)

def packet_callback(packet):
    timestamp = datetime.datetime.now()

    src_ip = packet[IP].src if IP in packet else "N/A"
    dst_ip = packet[IP].dst if IP in packet else "N/A"

    layer, transport_packet = get_transport_layer(packet)
    src_port = transport_packet.sport if transport_packet else "N/A"
    dst_port = transport_packet.dport if transport_packet else "N/A"
    app_layer_protocol = get_app_layer_protocol(src_port, dst_port)

    # Extract packet payload data
    if Raw in packet:
        payload = packet[Raw].load
    else:
        payload = None

    suspicious_src = is_suspicious_ip(src_ip)
    suspicious_dst = is_suspicious_ip(dst_ip)

    src_country = get_country(src_ip)
    dst_country = get_country(dst_ip)

    watchlist_src = is_watchlist_country(src_country)
    watchlist_dst = is_watchlist_country(dst_country)

    packet_info = f"{timestamp}: {packet.summary()} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {layer}"
    if app_layer_protocol:
        packet_info += f" | {app_layer_protocol}"
    print(packet_info)

    if payload:
        print(f"Payload: {payload}")

        # Detect keywords in payload and print them
        matches = detect_keywords(payload)
        if matches:
            print(f"Detected keywords: {', '.join(matches)}")

        # Extract domain from payload and check if it's suspicious
        domain = extract_domain(payload)
        if domain and is_suspicious_domain(domain):
            print(f"Suspicious domain detected: {domain}")

    # Check if the source or destination IP is suspicious
    if suspicious_src or suspicious_dst:
        print("Suspicious IP detected!")

    # Check if the source or destination country is on the watchlist
    if watchlist_src or watchlist_dst:
        print("Suspicious country detected!")

    # Log packet information to a file
    log_message = packet_info
    if payload:
        log_message += f"\nPayload: {payload}"
        if matches:
            log_message += f"\nDetected keywords: {', '.join(matches)}"
        if domain and is_suspicious_domain(domain):
            log_message += f"\nSuspicious domain detected: {domain}"
    if suspicious_src or suspicious_dst:
        log_message += "\nSuspicious IP detected!"
    if watchlist_src or watchlist_dst:
        log_message += "\nSuspicious country detected!"

    logging.info(log_message)
    
def main():
    parser = argparse.ArgumentParser(description='Packet analyzer')
    parser.add_argument('-f', '--file', metavar='file', help='Path to the pcap file for offline analysis')
    args = parser.parse_args()

    if args.file:
        print(f"Analyzing packets from pcap file: {args.file}")
        sniff(prn=packet_callback, store=True, filter="ip", offline=args.file)
    else:
        print("Capturing packets in real-time")
        sniff(prn=packet_callback, store=True, filter="ip")

if __name__ == '__main__':
    main()
