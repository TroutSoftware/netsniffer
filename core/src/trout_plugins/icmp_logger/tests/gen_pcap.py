#!/usr/bin/env python3


from scapy.all import *

print("Generating test pcaps for icmp logger")

data = []

# ICMP package "Destination Unreachable (Destination network unknown)"
data.append(Ether(type=2048)/
            IP(src="192.168.1.75",
               dst="192.168.1.75")/
            ICMP(type=3,
                 code=6)/
            IPerror(src="192.168.1.75",
                    dst="192.168.1.74")/
            ICMPerror(type=8,
                      code=0,
                      seq=2)/
            Raw(load="1234567890"))

# ICMP package "Destination Unreachable (Destination host unreachable)"
data.append(Ether(type=2048)/
            IP(src="192.168.1.75",
               dst="192.168.1.75")/
            ICMP(type=3,
                 code=1)/
            IPerror(src="192.168.1.75",
                    dst="192.168.1.74")/
            ICMPerror(type=8,
                      code=0,
                      seq=2)/
            Raw(load="1234567890"))


# ICMP package "Echo Reply"
data.append(Ether(type=2048)/
            IP(src="192.168.1.75",
               dst="192.168.1.75")/
            ICMP(type=0,
                 code=6)/
            IPerror(src="192.168.1.75",
                    dst="192.168.1.74")/
            ICMPerror(type=8,
                      code=0,
                      seq=2)/
            Raw(load="1234567890"))


data.append(Ether(src="00:11:11:11:11:11",
                  dst="00:11:22:33:44:55")/
            ARP(op=2,
                psrc="192.168.1.0",
                hwsrc="00:11:22:33:44:55",
                pdst="1.1.1.1",
                hwdst="00:11:11:11:11:11"))

wrpcap("testdata/icmp_multi.pcap", data)


