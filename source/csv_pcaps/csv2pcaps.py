#! /usr/bin/env python3
# vim:fenc=utf-8
#
# Copyright © 2024 cronoimpius <cronoimpius@r3dska>
#
# Distributed under terms of the MIT license.
'''
import csv
import time
from scapy.all import IP, TCP, Raw, wrpcap
import sys

input_file = sys.argv[1]
output_file = sys.argv[2]

# Function to convert timestamp to epoch time (in seconds)
def convert_to_epoch_time(timestamp):
    h, m, s = map(int, timestamp.split(":"))
    epoch_time = (h * 3600) + (m * 60) + s
    return epoch_time

# Function to create a packet from a CSV row
def create_packet(row):
    # Extract values from the CSV row
    packet_number = row[0]  # Not used in the packet creation but can be logged
    timestamp = row[1]
    duration = float(row[2])  # Packet duration in seconds (not used directly)
    protocol = row[3]
    src_ip = row[4]
    src_port = int(row[5])
    dst_ip = row[6]
    dst_port = int(row[7])
    pkts = int(row[8])  # Packet length (not used directly)
    bts = int(row[9])
    flags = row[10]  # TCP flags
    label = row[-1]  # Label (e.g., 'normal')

    # Convert timestamp to epoch time
    timestamp_epoch = convert_to_epoch_time(timestamp)

    # Build the IP and TCP layers
    ip_layer = IP(src=src_ip, dst=dst_ip)
    
    # TCP flags: We map 'SYN', 'ACK', etc., to Scapy flags
    flag_map = {
        'SYN': 'S',
        'ACK': 'A',
        'FIN': 'F',
        'RST': 'R',
        'PSH': 'P',
        'URG': 'U'
    }
    flag = flag_map.get(flags, '')  # Default to empty string if not matched

    # Create TCP layer with sequence and acknowledgment numbers
    tcp_layer = TCP(sport=src_port, dport=dst_port, flags=flag)

    # Create packet payload (optional) - assuming "....." is just filler for simplicity
    payload = b'label'  # Placeholder for actual payload data

    # Create the packet with the IP, TCP, and Raw (payload) layer
    if protocol == "TCP":
        packet = ip_layer / tcp_layer / Raw(load=payload)
    else:
        # For now, we handle only TCP packets in this script
        packet = ip_layer / tcp_layer / Raw(load=payload)

    return packet, timestamp_epoch

# Function to read the CSV file and generate the PCAP file
def convert_csv_to_pcap(csv_file, pcap_file):
    packets = []
    
    with open(csv_file, mode='r') as f:
        reader = csv.reader(f)
        for row in reader:
            # Create a packet from the CSV row
            packet, timestamp_epoch = create_packet(row)
            
            # Append the packet with timestamp (Scapy expects this format)
            packets.append((timestamp_epoch, packet))

    # Write the packets to the PCAP file
    wrpcap(pcap_file, [pkt[1] for pkt in packets])#, timestamp=packets[0][0])

# Main function to invoke the conversion
def main():
    convert_csv_to_pcap(input_file, output_file)
    print(f"PCAP file created: {output_file}")

# Run the script
if __name__ == "__main__":
    main()
'''
import csv
from scapy.all import *
import ipaddress
import random
import sys
# Define the input CSV file and output PCAP file
input_csv = sys.argv[1]
output_pcap = sys.argv[2]

def parse_csv_row(row):
    """
    #Parse a CSV row into a Scapy packet.
"""
    packet_number = row[0]  # Not used in the packet creation but can be logged
    timestamp = row[1]
    protocol = row[3]
    src_ip = row[4]
    dst_ip = row[6]
    src_port = int(row[5])
    dst_port = int(row[7])
    packet_size = int(row[8])
    bts = int(row[9])
    flags = row[10]  # TCP flags
    label = row[11]  # Label (e.g., 'normal')
    # Create the IP layer
    ip_layer = IP(src=src_ip, dst=dst_ip)

    # TCP flags: We map 'SYN', 'ACK', etc., to Scapy flags
    flag_map = {
        'SYN': 'S',
        'ACK': 'A',
        'FIN': 'F',
        'RST': 'R',
        'PSH': 'P',
        'URG': 'U'
    }
    flag = flag_map.get(flags, '')  # Default to empty string if not matched
    
    # Create the appropriate transport layer based on the protocol
    if protocol == "TCP":
        transport_layer = TCP(sport=src_port, dport=dst_port, flags = flag)
    elif protocol == "ICMP":
        transport_layer = ICMP()
    else:
        raise ValueError(f"Unsupported protocol: {protocol}")

    # Generate the packet (combine IP and transport layers)
    packet = ip_layer / transport_layer

    # Set packet size by padding (if needed)
    if len(packet) < packet_size:
        packet = packet / Raw(load=str.encode(label) * (packet_size - len(packet)))
    
    return packet

def csv_to_pcap(input_csv, output_pcap):
    """
    #Convert the CSV file to a PCAP file.
"""
    packets = []
    
    # Open the CSV file and read it line by line
    with open(input_csv, 'r') as file:
        csv_reader = csv.reader(file)
        for row in csv_reader:
            # Skip empty rows or rows that don't have the expected number of columns
            if len(row) < 9:
                continue

            # Parse the row into a Scapy packet
            try:
                packet = parse_csv_row(row)
                packets.append(packet)
            except ValueError as e:
                print(f"Skipping invalid row: {row} - {e}")
                continue

    # Write the packets to a PCAP file
    wrpcap(output_pcap, packets)
    print(f"PCAP file '{output_pcap}' created successfully!")

# Run the conversion
csv_to_pcap(input_csv, output_pcap)

