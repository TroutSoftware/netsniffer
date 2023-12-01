# Simplistic makefile

# Check for cbindgen being installed (used to autogenerate C header files from rust code)
ifeq (, $(shell which cbindgen))
$(error "You need to have a valid cbindgen installed to create the bindings between rust and C, e.g. on Ubuntu: sudo apt install cbindgen")
endif

BUILDFOLDER=build
RUSTBUILD=rust_lib/target
RUSTLIBD=$(RUSTBUILD)/debug/librust_lib.a
RUSTCLINK=$(BUILDFOLDER)/rustlink.h
TARGET=trafficlog.so
TESTDATA=test_data
TESTCONFIG=test_config
INCLUDEDIR=/usr/local/include/snort

$(TARGET): $(RUSTLIBD) plugin_glue/inspector.cc
ifeq (,$(wildcard $(BUILDFOLDER)))
	mkdir $(BUILDFOLDER)
endif
	cd rust_lib; cbindgen -o ../$(RUSTCLINK)
	g++ -fPIC -shared plugin_glue/inspector.cc $(RUSTLIBD) -I $(INCLUDEDIR) -I $(BUILDFOLDER) -o $(BUILDFOLDER)/$(TARGET)

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
	snort -v -r $(TESTDATA)/profinet.pcap -c $(TESTCONFIG)/myconf.lua --plugin-path . -A alert_talos --warn-all 

.PHONY: test-scan
test-scan: $(TARGET)
	snort -v --pcap-dir $(TESTDATA) -c $(TESTCONFIG)/myconf.lua --plugin-path . -A alert_talos --warn-all -z 2 -q
