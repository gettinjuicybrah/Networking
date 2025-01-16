"""
Simple Packet Sniffer Tool

This script uses the Scapy library to capture network packets in real-time and display
basic information for each packet including:
    - Source IP address
    - Destination IP address
    - Protocol type (TCP, UDP, ICMP, or others)
    - Payload size in bytes

Requirements:
    - Python 3.x
    - Scapy (install via: pip install scapy)

Usage:
    Run the script with root/administrator privileges:
        sudo python packet_sniffer.py

Press Ctrl+C to stop the packet sniffer.
"""

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def process_packet(packet):
    """
    Callback function to process each captured packet.

    This function checks if the packet contains an IP layer, then extracts the following details:
      - Source IP address
      - Destination IP address
      - Protocol type (TCP, UDP, ICMP, or others)
      - Payload size (calculated from the data portion of the respective protocol layer)

    Args:
        packet: A Scapy packet object captured by the sniffer.
    """
    # Ensure the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Default values
        proto_name = f"Other (Protocol Number: {ip_layer.proto})"
        payload = b""

        # Identify the protocol and extract payload accordingly
        if TCP in packet:
            proto_name = "TCP"
            payload = bytes(packet[TCP].payload)
        elif UDP in packet:
            proto_name = "UDP"
            payload = bytes(packet[UDP].payload)
        elif ICMP in packet:
            proto_name = "ICMP"
            payload = bytes(packet[ICMP].payload)
        else:
            # If not TCP/UDP/ICMP, try to extract the payload from the IP layer
            payload = bytes(ip_layer.payload)

        payload_size = len(payload)

        # Print the extracted packet details
        print(f"Source: {src_ip} -> Destination: {dst_ip} | Protocol: {proto_name} | Payload Size: {payload_size} bytes")
    else:
        # If there's no IP layer, skip processing
        print("Packet does not contain an IP layer, skipping...")

def main():
    """
    Main function to start the packet sniffer.

    Uses Scapy's sniff function to capture packets. The callback 'process_packet'
    is called for each captured packet. The 'store=0' parameter prevents storing packets in memory.
    """
    print("Starting packet sniffer... Press Ctrl+C to stop.")

    # Start capturing packets with the callback function process_packet
    sniff(prn=process_packet, store=0)

if __name__ == '__main__':
    main()