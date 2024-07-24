ISNORT := /opt/snort/include/snort
SNORT := /opt/snort/bin/snort

MODULE = dhcp_option.so
CC_SOURCES = flow_data.cc inspector.cc ips_option.cc ips_option_ip_filter.cc snort_plugins.cc
CC_HEADERS = flow_data.h  inspector.h  ips_option.h  ips_option_ip_filter.h

.PHONY: test test-data clean format
test:
	sh3 -sanitize none -o $(MODULE) -i "$(CC_SOURCES)" $(TEST_LIMIT)

test-data: p/$(MODULE)
	$(SNORT) -v -c ../../test_config/cfg.lua --plugin-path p -A talos --pcap-dir ../../test_data --warn-all

clean:
	rm p/$(MODULE)

format:
	clang-format -i $(CC_SOURCES) $(CC_HEADERS)

p/$(MODULE): $(CC_SOURCES)
	g++ -O1 -std=c++2b -fPIC -Wall -Wextra -g -fsanitize=undefined -shared -I $(ISNORT)  $< -o $@
