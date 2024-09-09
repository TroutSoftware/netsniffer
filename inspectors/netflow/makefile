ISNORT := /opt/snort/include/snort
SNORT := /opt/snort/bin/snort
OUTPUTDIR := p
MAKEDIR := .m

MODULE = netflow.so

CC_SOURCES = \
	alert_lioli.cc \
	flow_data.cc \
	inspector.cc \
	ips_lioli_bind.cc \
	lioli.cc \
	log_lorth.cc \
	log_txt.cc \
	output_to_file.cc \
	output_to_pipe.cc \
	output_to_stdout.cc \
	snort_plugins.cc

CC_HEADERS = \
	alert_lioli.h \
	flow_data.h \
	ips_lioli_bind.h \
	lioli.h \
	lioli_tree_generator.h \
	log_lorth.h \
	log_txt.h \
	log_lioli_tree.h \
	output_to_file.h \
	output_to_pipe.h \
	output_to_stdout.h

OBJS=$(addprefix $(MAKEDIR)/, $(subst .cc,.o,$(CC_SOURCES)))
DEPS=$(addprefix $(MAKEDIR)/, $(subst .cc,.d,$(CC_SOURCES)))

.PHONY: test test-data clean format build oldstyle
test:
	sh3 -sanitize none -o $(MODULE) -i "$(CC_SOURCES)" $(TEST_LIMIT)

test-data: $(OUTPUTDIR)/$(MODULE)
	$(SNORT) -v -c ../../test_config/cfg.lua --plugin-path $(OUTPUTDIR) --pcap-dir ../../test_data --warn-all

test-local: $(OUTPUTDIR)/$(MODULE)
	$(SNORT) -v -c tests/test-local.lua --plugin-path $(OUTPUTDIR) --pcap-dir pcaps --warn-all

$(MAKEDIR):
	mkdir $(MAKEDIR)

$(OUTPUTDIR):
	mkdir $(OUTPUTDIR)

clean:
	if [ -f $(OUTPUTDIR)/$(MODULE) ]; then rm $(OUTPUTDIR)/$(MODULE); fi
	if [ -d $(MAKEDIR) ]; then rm -r $(MAKEDIR); fi

format:
	clang-format -i $(CC_SOURCES) $(CC_HEADERS)

build: $(OUTPUTDIR)/$(MODULE)
	@echo "Build done"

oldstyle: $(CC_SOURCES) $(CC_HEADERS)
	g++ -O1 -std=c++2b -fPIC -Wall -Wextra -g -fsanitize=undefined -shared -I $(ISNORT) $(CC_SOURCES) -o $@

-include ${DEPS}

$(MAKEDIR)/%.o : %.cc | $(MAKEDIR)
	g++ -MMD -MT '$(patsubst %.cc,$(MAKEDIR)/%.o,$<)' -pipe -O1 -std=c++2b -fPIC -Wall -Wextra -g -I $(ISNORT) -c $< -o $@

$(OUTPUTDIR)/$(MODULE): $(OBJS) | $(OUTPUTDIR)
	echo $CC_SOURCES
	g++ $(OBJS) -fPIC -shared -O1 -Wall -Wextra -o $@

