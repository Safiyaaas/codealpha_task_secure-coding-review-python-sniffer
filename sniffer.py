from scapy.all import sniff, IP, TCP, UDP, Ether

def packet_callback(packet):
    """
    Callback function to process each captured packet.
    Extracts and displays key information.
    """
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
        
        # Display packet info
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {proto_name}")
        if src_port and dst_port:
            print(f"Source Port: {src_port}")
            print(f"Destination Port: {dst_port}")
        print(f"Payload (first 50 bytes): {payload[:50]}")
        print("-" * 50)

# Main function to start sniffing
def main():
    interface = "eth0"  # Change this to your network interface (e.g., "wlan0" for Wi-Fi)
    print(f"Starting packet sniffer on interface: {interface}")
    print("Press Ctrl+C to stop.")
    
    # Sniff packets indefinitely
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
