use std::path::Path;

fn main() {
    let snort_includes = Path::new("/opt/snort/include/snort");

    cxx_build::bridge("test_packet.rs")
        .include(snort_includes)
        .compile("test_inspector");
}
