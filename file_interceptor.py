#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet.haslayer[scapy.TCP].dport == 80:
            print("HTTP Request")
            print(scapy_packet.show())
            if ".exe" in scapy_packet[scapy.Raw].load:
                print("[+] exe Request")
                print(scapy_packet.show())
        elif scapy_packet.haslayer[scapy.TCP].sport == 80:
            print("HTTP Response")
            print(scapy_packet.show())

    packet.accept()
