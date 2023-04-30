import argparse
import datetime
import re
import json
import tldextract
import logging
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.sctp import SCTP
from geoip2.database import Reader

# Configure the logging system
logging.basicConfig(
    filename="packet_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Load GeoLite2 local database
geolite2_reader = Reader('GeoLite2-Country.mmdb')

# Load configuration from a JSON file
with open("config.json", "r") as f:
    config = json.load(f)

keywords = config["keywords"]
pattern = re.compile("|".join(keywords))

suspicious_ips = config["suspicious_ips"]
suspicious_domains = config["suspicious_domains"]
watchlist_countries = config["watchlist_countries"]

# Add support for more application layer protocols
app_ports = {
    80: "HTTP",
    443: "HTTPS",
    20: "FTP Data",
    21: "FTP Control",
    53: "DNS",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
}

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
        response = geolite2_reader.country(ip)
        return response.country.name
    except:
        return None

def is_watchlist_country(country):
    return country in watchlist_countries

def extract_domain(payload):
    return tldextract.extract(payload).domain

def is_suspicious_domain(domain):
    return domain in suspicious_domains

def get_app_layer_protocol(src_port, dst_port):
    return app_ports.get(src_port) or app_ports.get(dst_port)

def log_packet(packet_info, payload, matches, domain, suspicious_src, suspicious_dst, watchlist_src, watchlist_dst):
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

def packet_callback(packet):
    # Use user-provided custom BPF filter
    if config["custom_filter"]:
        if not packet.haslayer(eval(config["custom_filter"])):
            return

    # Remaining packet_callback code logic

def main():
    parser = argparse.ArgumentParser(description='Packet analyzer')
    parser.add_argument('-f', '--file', metavar='file', help='Path to the pcap file for offline analysis')
    parser.add_argument('-i', '--iface', metavar='iface', help='Interface to capture live packets')
    args = parser.parse_args()

    if args.file:
        print(f"Analyzing packets from pcap file: {args.file}")
        sniff(prn=packet_callback, store=False, filter="ip", offline=args.file)
    else:
        iface = args.iface or conf.iface
        print(f"Capturing packets in real-time on interface {iface}")
        sniff(prn=packet_callback, store=False, filter="ip", iface=iface)

if __name__ == '__main__':
    main()
