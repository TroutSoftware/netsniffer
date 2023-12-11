# Build inspectors
#
# The project is complex, with C++ / rust interop, and the final result is a shared object with a specific layout:
# https://github.com/snort3/snort3/blob/master/doc/devel/extending.txt
#
# This makefile tries to keep most of the pain out of the way:
#  - code under cxxbridge and include/cxxbridge contains generic snort interop features
#  - new inspectors should be below inspectors, created with cargo new, and compiling to static lib
#  - new inspectors should have a dedicated inspector.cc to implement the required API
#  - inspector.cc should include the headers files initially (order matters!), and the .cc files before the terminal SO_PUBLIC line
#
# The compilation process takes then care of generating c++ binding code, and bundling everything under the final shared object.
#
# The testing procedure is currently very raw, and efforts will be done in this space

INSPECTORS := network_mapping
SOLIBS := $(addsuffix .so, $(addprefix p/, $(INSPECTORS)))

SNORT := /opt/snort/bin/snort

all: $(SOLIBS)
	$(SNORT) -v -c test_config/min_cfg.lua --plugin-path p -A talos -r test_data/tcp_flow.pcap --warn-all

.PHONY: clean
clean:
	cargo clean
	rm $(SOLIBS)

p/%.so: inspectors/%/src/inspector.cc target/debug/lib%.a | include/cxxbridge/common.rs.cc include/cxxbridge/common.rs.h include/cxxbridge/%.rs.h include/cxxbridge/%.rs.cc
	g++ -O1 -fPIC -Wall -shared -I include/snort -I include/cxxbridge  $^ -o $@

.INTERMEDIATE: include/cxxbridge/common.rs.cc include/cxxbridge/common.rs.h

include/cxxbridge/common.rs.cc include/cxxbridge/common.rs.h: cxxbridge/src/lib.rs
	cxxbridge $<            -o include/cxxbridge/common.rs.cc
	cxxbridge $< --header -o include/cxxbridge/common.rs.h

include/cxxbridge/%.rs.h: inspectors/%/src/lib.rs
	cxxbridge $< --header -o $@

include/cxxbridge/%.rs.cc: inspectors/%/src/lib.rs
	cxxbridge $< -o $@

target/debug/lib%.a: inspectors/%/src/lib.rs
	cargo build

fmt:
	cargo fmt
	clang-format -i $(wildcard include/cxxbridge/*.cc)
	clang-format -i $(wildcard include/cxxbridge/*.h)
	clang-format -i $(addsuffix /src/inspector.cc, $(addprefix inspectors/, $(INSPECTORS)))

install:
	apt install snort-dev clang-format cxxbridge-cmd
	cxxbridge --header > include/cxxbridge/rust.h
	ln -s /opt/snort/include/snort src/include/snort