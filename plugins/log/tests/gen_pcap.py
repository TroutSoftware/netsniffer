#!/usr/bin/env python3


from scapy.all import *

print("Generating test pcap")

data = []

pkg = IP()/UDP()/"PAYLOAD"
pkg.src = f"2.2.0.0"
pkg.sport = 10
pkg.dst = f"2.0.0.2"
pkg.dport = 20
pkg = Ether(dst="45:3c:b0:56:5e:d4", src="6d:48:a3:39:db:8c")/pkg
data.append(pkg)
data.append(pkg)
data.append(pkg)


wrpcap("testdata/udp_stream.pcap", data)
