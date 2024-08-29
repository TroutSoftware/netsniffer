ISNORT := /opt/snort/include/snort
SNORT := /opt/snort/bin/snort

MODULE = netflow.so
CC_SOURCES =					\
	alert_lioli.cc			\
	flow_data.cc				\
	inspector.cc				\
	ips_lioli_bind.cc		\
	lioli.cpp						\
	log_txt.cc					\
	snort_plugins.cc

CC_HEADERS =								\
	alert_lioli.h							\
	flow_data.h								\
	ips_lioli_bind.h					\
	lioli.h										\
	lioli_tree_generator.h		\
	log_txt.h									\
	log_lioli_tree.h					\

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
