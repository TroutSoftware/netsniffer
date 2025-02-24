#!/usr/bin/env python3

import argparse
from scapy.all import *

print("Hello world")

parser = argparse.ArgumentParser(description='Script fixing ip checksums from pcap files')

parser.add_argument('infile', nargs=1 , help='Specifies the pcap file to read')
parser.add_argument('outfile', nargs=1 , help='Specifies the pcap file to write')

args = parser.parse_args()

print("Reading: ", args.infile)

packets = rdpcap(args.infile[0])

print("Scanning...")
for packet in packets:
  if packet.haslayer(IP):
    del packet[IP].chksum
  if packet.haslayer(TCP):
    del packet[TCP].chksum
  if packet.haslayer(UDP):
    del packet[UDP].chksum

print("Writing: ", args.outfile[0])
wrpcap(args.outfile[0], packets)
