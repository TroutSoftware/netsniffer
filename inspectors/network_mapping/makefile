ISNORT := /opt/snort/include/snort
TARGET := ../../target
IGEN := $(TARGET)/cxxbridge/
SNORT := /opt/snort/bin/snort

.PHONY: test test-data clean
test: p/network_mapping.so
	$(SNORT) -v -c cfg.lua --plugin-path p -A talos -r dns8888.pcap --warn-all

test-data: p/network_mapping.so
	$(SNORT) -v -c cfg.lua --plugin-path p -A talos --pcap-dir ../../test_data --warn-all

clean:
	cargo clean
	rm p/network_mapping.so

p/network_mapping.so: inspector.cc inspector.rs
	cargo build -r
	g++ -O1 -fPIC -Wall -shared -I $(ISNORT) -I $(IGEN) $< $(TARGET)/release/libnetwork_mapping.a -o $@
