#!/usr/bin/env python3


from scapy.all import *

print("Generating test pcaps for trout_netflow2")

data = []



pkt_tcp_v4 =  Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB") / \
              IP(src="8.8.8.8", dst="10.0.0.1") / \
              TCP(sport=12345, dport=80, flags="S")
data.append(pkt_tcp_v4)

pkt_udp_v4 =  Ether(src="00:11:22:33:44:56", dst="66:77:88:99:AA:BA") / \
              IP(src="192.168.0.101", dst="8.8.8.8") / \
              UDP(sport=54321, dport=53)
data.append(pkt_udp_v4)

pkt_icmp_v4 = Ether(src="00:11:22:33:44:57", dst="66:77:88:99:AA:B9") / \
              IP(src="192.168.1.101", dst="10.0.0.1") / \
              ICMP(type=8)
data.append(pkt_icmp_v4)

pkt_tcp_v6 =  Ether(src="00:11:22:33:44:58", dst="66:77:88:99:AA:B8") / \
              IPv6(src="2001:db8::1", dst="2001:db8::2") / \
              TCP(dport=443, flags="S")
data.append(pkt_tcp_v6)

pkt_udp_v6 =  Ether(src="00:11:22:33:44:59", dst="66:77:88:99:AA:B7") / \
              IPv6(src="2001:db8::1", dst="2001:db8::2") / \
              UDP(dport=5000)
data.append(pkt_udp_v6)

pkt_gre =     Ether(src="00:11:22:33:44:5A", dst="66:77:88:99:AA:B6") / \
              IP(src="1.1.1.1", dst="2.2.2.2", proto=47) / \
              GRE() / \
              IP(src="192.168.1.50", dst="192.168.1.60") / \
              TCP(dport=22, flags="S")
data.append(pkt_gre)

pkt_sctp =    Ether(src="00:11:22:33:44:5B", dst="66:77:88:99:AA:B5") / \
              IP(src="192.168.1.101", dst="10.0.0.1") / \
              SCTP(sport=1000, dport=2000)
data.append(pkt_sctp)

wrpcap("testdata/netflow2_pkt_types.pcap", data)
