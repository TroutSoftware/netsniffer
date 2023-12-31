ISNORT := /opt/snort/include/snort
SNORT := /opt/snort/bin/snort

.PHONY: test test-data clean
test: p/network_mapping.so
	$(SNORT) -v -c cfg.lua --plugin-path p -A talos -r dns8888.pcap --warn-all

test-data: p/network_mapping.so
	$(SNORT) -v -c cfg.lua --plugin-path p -A talos --pcap-dir ../../test_data --warn-all

clean:
	rm p/network_mapping.so

p/network_mapping.so: inspector.cc
	g++ -O1 -std=c++2b -fPIC -Wall -Wextra -g -fsanitize=undefined -shared -I $(ISNORT)  $< -o $@
