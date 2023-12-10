# This should probably be top-level!

BINDGEN := $(addprefix include/cxxbridge/network_mapping/, lib.rs.cc lib.rs.h)

network_mapping.so: src/inspector.cc target/debug/libnetwork_mapping.a include/cxxbridge/network_mapping/lib.rs.cc
	g++ -fsanitize=address -O1 -fPIC -Wall -shared $^ -I include/snort -I include/cxxbridge -o $@

$(BINDGEN): src/lib.rs
	cxxbridge src/lib.rs --header > include/cxxbridge/network_mapping/lib.rs.h
	cxxbridge src/lib.rs > include/cxxbridge/network_mapping/lib.rs.cc

include/cxxbridge/rust.h:
	cxxbridge --header > $@

target/debug/libnetwork_mapping.a: src/lib.rs
	cargo build

