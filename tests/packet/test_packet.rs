#![crate_type = "staticlib"]

#[cxx::bridge]
mod ffi {
    extern "C++" {
        include!("protocols/packet.h");
        #[namespace = "snort"]
        type Packet = cxxbridge::packet::ffi::Packet;
    }

    extern "Rust" {
        fn eval_packet(pkt: &Packet);
    }
}

use cxxbridge::packet::Packet;

fn eval_packet(pkt: &ffi::Packet) {
    let pkt = Packet::new(pkt);
    let pl = pkt.payload();

    if pl.len() == 0 {
        println!("empty packet");
    }
}
