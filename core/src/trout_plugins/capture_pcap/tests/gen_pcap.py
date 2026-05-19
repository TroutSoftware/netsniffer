#!/usr/bin/env python3


from scapy.all import *

print("Generating test pcaps")

data = []

for n in range(10):
  for p in range (10):
    pkg = IP()/UDP()/"PAYLOAD"
    pkg.src = f"2.{n}.0.0"
    pkg.sport = 10
    pkg.dst = f"2.0.0.{p}"
    pkg.dport = 20
    pkg = Ether(dst="00:00:00:00:00:00", src="00:00:00:00:00:00")/pkg
    data.append(pkg)
    data.append(pkg)  # This makes multi package udp streams and makes it possible to check if hints gets inversted in their logic

    pkg = IP()/TCP()/"PAYLOAD"
    pkg.src = f"3.{n}.0.0"
    pkg.sport = 30
    pkg.dst = f"3.0.0.{p}"
    pkg.dport = 40
    pkg = Ether(dst="00:00:00:00:00:00", src="00:00:00:00:00:00")/pkg
    data.append(pkg)



wrpcap("testdata/test.pcap", data)
