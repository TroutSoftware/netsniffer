#![crate_type = "staticlib"]

use cxxbridge::inspector::Inspector;
use cxxbridge::packet::Packet;

pub struct PacketInspector {}

impl Inspector for PacketInspector {
    fn new<'a>() -> &'a PacketInspector {
        &PacketInspector {}
    }

    fn eval(&self, pkt: &Packet) {
        let pl = pkt.payload();

        if pl.len() == 0 {
            println!("empty packet");
        }
    }
}

#[cxx::bridge]
mod ffi {
    #[namespace = "snort"]
    extern "C++" {
        include!("framework/inspector.h");

        type Module;
    }
}

pub fn create_inspector(module: *const ffi::Module) -> cxxbridge::inspector::ffi::RustInspector {
    cxxbridge::inspector::create_inspector(module, PacketInspector::new())
}
