import os
import re
import logging
from scapy.all import sniff, IP, TCP, UDP, Ether

# Set up secure logging (instead of print for sensitive data)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def packet_callback(packet):
    """
    Secure callback: Processes packets with sanity checks and redaction.
    """
    if not packet or len(packet) > 1500:  # Basic sanity check to prevent malformed packet issues
        return
    
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        # Determine protocol name
        if protocol == 6:
            proto_name = "TCP"
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                payload = bytes(packet[TCP].payload) if packet[TCP].payload else b""
        elif protocol == 17:
            proto_name = "UDP"
            if UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                payload = bytes(packet[UDP].payload) if packet[UDP].payload else b""
        else:
            proto_name = f"Other ({protocol})"
            src_port = dst_port = None
            payload = bytes(packet[IP].payload) if packet[IP].payload else b""
        
        # Secure display: Redact payloads to prevent data exposure
        logging.info(f"Source IP: {src_ip}")
        logging.info(f"Destination IP: {dst_ip}")
        logging.info(f"Protocol: {proto_name}")
        if src_port and dst_port:
            logging.info(f"Source Port: {src_port}")
            logging.info(f"Destination Port: {dst_port}")
        logging.info("Payload: [REDACTED FOR SECURITY]")  # No raw data printed
        logging.info("-" * 50)

def main():
    # Privilege check and drop
    if os.geteuid() != 0:
        logging.error("Run with sudo for raw access. Exiting.")
        return
    os.seteuid(os.getuid())  # Drop privileges after initial check (if applicable)
    
    # Secure interface input with validation
    interface = input("Enter network interface (e.g., eth0): ").strip()
    if not re.match(r'^[a-zA-Z0-9]+$', interface):
        logging.error("Invalid interface name. Exiting.")
        return
    
    logging.info(f"Starting secure packet sniffer on interface: {interface}")
    logging.info("Press Ctrl+C to stop.")
    
    # Sniff with error handling
    try:
        sniff(iface=interface, prn=packet_callback, store=0)
    except Exception as e:
        logging.error(f"Sniffing error: {e}")

if __name__ == "__main__":
    main()
