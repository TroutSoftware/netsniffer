ISNORT := /opt/snort/include/snort
SNORT := /opt/snort/bin/snort

MODULE = network_mapping.so
CC_SOURCES = inspector.cc

.PHONY: test test-data clean format
test:
	sh3 -o $(MODULE) -i $(CC_SOURCES) $(TEST_LIMIT)

test-data: p/network_mapping.so
	$(SNORT) -v -c ../../test_config/cfg.lua --plugin-path p -A talos --pcap-dir ../../test_data --warn-all

clean:
	rm p/network_mapping.so

format:
	clang-format -i $(CC_SOURCES)

p/$(MODULE): $(CC_SOURCES)
	g++ -O1 -std=c++2b -fPIC -Wall -Wextra -g -fsanitize=undefined -shared -I $(ISNORT)  $< -o $@
