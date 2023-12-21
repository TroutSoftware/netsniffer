use std::path::Path;

fn main() {
    let snort_includes = Path::new("/opt/snort/include/snort");

    cxx_build::bridge("inspector.rs")
        .include(snort_includes)
        .compile("network_mapping");

    //TODO g++ -O1 -fPIC -Wall -shared -I $(ISNORT) -I $(IGEN) $< $(TARGET)/debug/libtest_packet.a -o $@
}
