ISNORT := /opt/snort/include/snort
TARGET := ../../target
IGEN := $(TARGET)/cxxbridge/
SNORT := /opt/snort/bin/snort

.PHONY: test clean
test: p/test_packet.so
	$(SNORT) -v -c cfg.lua --plugin-path p -A talos -r dns8888.pcap --warn-all

clean:
	cargo clean
	rm p/test_packet.so

p/test_packet.so: test_inspector.cc test_packet.rs
	cargo build -r
	g++ -O1 -fPIC -Wall -shared -I $(ISNORT) -I $(IGEN) $< $(TARGET)/release/libtest_packet.a -o $@
