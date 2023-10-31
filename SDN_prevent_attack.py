import socket
from scapy.contrib.openflow3 import *
from scapy.all import *
import subprocess

# Set the OpenFlow controller port
OF_PORT = 6653

# Initialize a dictionary to store the number of packets received from each switch
switch_packet_count = {}

# Create a sniffing function to identify packet_in messages
def sniff_packet_in(iface):
    sniff(iface=iface, filter="tcp", prn=lambda packet: check_packet_in(packet), stop_filter=lambda _: False)

# Function to add iptables rule
def add_iptables_rule(switch_ip, switch_port):
    iptables_rule = "sudo iptables -A INPUT -p tcp --source-port {} -s {} --dport {} -j DROP".format(switch_port, switch_ip, OF_PORT)
    subprocess.run(iptables_rule, shell=True)
    print("Iptables rule added: {}".format(iptables_rule))

# Function to check if the packet is a packet_in message
def check_packet_in(packet):
    if TCP in packet and packet[TCP].dport == OF_PORT and packet.haslayer(OFPTPacketIn):
        # Get the source IP and port of the sender
        switch_ip = packet[IP].src
        switch_port = packet[TCP].sport

        # Create a unique key for the combination of switch IP and source port
        key = (switch_ip, switch_port)

        # Increment the number of packets received from the switch and port
        switch_packet_count[key] = switch_packet_count.get(key, 0) + 1

        # Check if the threshold has been exceeded
        if switch_packet_count[key] > 100:
            # Send an alert message
            print("Alert: More than 100 packet_in messages received from switch {}:{}".format(switch_ip, switch_port))

            # Add iptables rule to block packets
            add_iptables_rule(switch_ip, switch_port)

# Start sniffing for packet_in messages
sniff_packet_in("enp0s3")
