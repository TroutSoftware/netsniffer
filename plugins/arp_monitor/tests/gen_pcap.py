#!/usr/bin/env python3


from scapy.all import *

print("Generating test pcaps for arp monitor")

data = []


data.append(Ether(src="00:11:22:33:44:55",
                  dst="ff:ff:ff:ff:ff:ff")/
            ARP(op=1,
                psrc="1.1.1.1",
                hwsrc="00:11:22:33:44:55",
                pdst="192.168.1.0"))

data.append(Ether(src="00:11:11:11:11:11",
                  dst="00:11:22:33:44:55")/
            ARP(op=2,
                psrc="192.168.1.0",
                hwsrc="00:11:22:33:44:55",
                pdst="1.1.1.1",
                hwdst="00:11:11:11:11:11"))

wrpcap("req_reply.pcap", data)


data.append(Ether(src="11:22:33:44:00_00",
                  dst="ff:ff:ff:ff:ff:ff")/
            ARP(op=1,
                psrc="1.2.3.4",
                hwsrc="11:22:33:44:00:00",
                pdst="2.2.2.2"))

wrpcap("more_req.pcap", data)

data.append(Ether(src="22:22:22:22:00:00",
                  dst="11:22:33:44:00:00")/
            ARP(op=2,
                psrc="2.2.2.2",
                hwsrc="22:22:22:22:00:00",
                pdst="1.2.3.4",
                hwdst="11:22:33:44:00:00"))

data.append(Ether(src="22:22:22:22:00:00",
                  dst="11:22:33:44:00:00")/
            ARP(op=2,
                psrc="2.2.2.2",
                hwsrc="22:22:22:22:00:00",
                pdst="1.2.3.4",
                hwdst="11:22:33:44:00:00"))

wrpcap("more_reply.pcap", data)

data = []

for n in range(10):
   data.append( Ether(src=f"{n}0:12:34:56:78:90",
                      dst="ff:ff:ff:ff:ff:ff")/
                ARP(op=1,
                    psrc=f"{n}.1.2.3",
                    hwsrc=f"{n}0:12:34:56:78:90",
                    pdst=f"192.168.1.{n}"))

wrpcap("10_req.pcap", data)
