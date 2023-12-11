# Simplistic makefile

BUILDFOLDER=build
RUSTBUILD=rust_lib/target
RUSTLIBD=$(RUSTBUILD)/debug/librust_lib.a
TARGET=experimental.so
TESTDATA=test_data
INCLUDEDIR=/usr/local/include/snort

$(TARGET): $(RUSTLIBD) plugin_glue/inspector.cc plugin_glue/type_ips_option.cc
ifeq (,$(wildcard $(BUILDFOLDER)))
	mkdir $(BUILDFOLDER)
endif
	g++ -fPIC -shared plugin_glue/inspector.cc plugin_glue/type_ips_option.cc $(RUSTLIBD) -I $(INCLUDEDIR) -o $(BUILDFOLDER)/$(TARGET)

.PHONY: $(RUSTLIBD)
$(RUSTLIBD):
	cd rust_lib; cargo build

.PHONY: clean
clean:
ifneq (,$(wildcard $(BUILDFOLDER)))
	rm -r $(BUILDFOLDER)
endif
ifneq (,$(wildcard $(RUSTBUILD)))
	rm -r $(RUSTBUILD)
endif
ifneq (,$(wildcard $(TARGET)))
	rm $(TARGET)
endif

.PHONY: demo
demo: $(TARGET)
	snort -v -r $(TESTDATA)/profinet.pcap -c $(TESTDATA)/myconf.lua --plugin-path . -A alert_talos --warn-all
