ISNORT := /opt/snort/include/snort
IGEN := target/cxxbridge/
SNORT := /opt/snort/bin/snort

.PHONY: test clean
test: p/test_packet.so
	$(SNORT) -v -c cfg.lua --plugin-path p -A talos -r dns8888.pcap -q

clean:
	cargo clean
	rm p/test_packet.so

p/test_packet.so: test_inspector.cc test_packet.rs
	cargo build
	g++ -O1 -fPIC -Wall -shared -I $(ISNORT) -I $(IGEN) $< target/debug/libtest_packet.a -o $@
