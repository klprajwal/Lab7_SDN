import socket
from threading import Thread, Event
from scapy.all import *

ip = None
port = None
terminate_flag = Event()

def check_port_num(packet):
    global ip, port
    if TCP in packet:
        if packet[TCP].sport in [6653, 6633]:
            print("Controller info found as, Source Port:{} and Source IP:{}".format(packet[TCP].sport,packet[IP].src))
            ip = packet[IP].src
            port = packet[TCP].sport
            terminate_flag.set()
        elif packet[TCP].dport in [6653, 6633]:
            print("controller info found as, Destination Port:{} and Destination IP:{}".format(packet[TCP].dport,packet[IP].dst))
            ip = packet[IP].dst
            port = packet[TCP].dport
            terminate_flag.set()

def sniffer():
    sniff(iface="eth1", filter="tcp", prn=check_port_num, stop_filter=lambda _: terminate_flag.is_set())

t1 = Thread(target=sniffer)
t1.start()
t1.join()

def openflow_packet_in(ip, port, source_port):
    # Create an IP layer
    ip_layer = IP(dst=ip)

    # Create a TCP layer with the desired source and destination ports
    tcp_layer = TCP(dport=port, sport=source_port)

    # Replace this with your actual binary OpenFlow packet_in message
    ofp_packet_in = b'\x01\x0a'

    # Combine the layers to form the complete packet
    packet = ip_layer / tcp_layer / ofp_packet_in

    # Send the packet
    send(packet)

def thread2():
    global ip, port

    while ip is None or port is None:
        pass

    source_port = 1111  # Set the source port to 1111

    for _ in range(125):
        openflow_packet_in(ip, port, source_port)

t2 = Thread(target=thread2)
t2.start()

