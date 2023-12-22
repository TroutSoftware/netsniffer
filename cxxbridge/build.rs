use std::path::Path;

fn main() {
    let snort_includes = Path::new("/opt/snort/include/snort");

    cxx_build::bridges(vec!["src/lib.rs", "src/sfip.rs", "src/packet.rs", "src/data_event.rs", "src/flow.rs",])
        .include("src")
        .include(snort_includes)
        .compile("cxxbridge");
}
