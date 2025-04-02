redo-ifchange  envrc
for f in pcaps/*.pcap; do
  tmp="${f%.pcap}.tsv"
  redo-ifchange output/${tmp#pcaps/}  
done




