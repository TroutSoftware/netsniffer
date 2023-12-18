#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("protocols/packet.h");
        include!("packet.cc");

        #[namespace = "snort"]
        pub type Packet;

        fn has_ip(&self) -> bool;
        fn get_type(&self) -> *const c_char;
        fn is_tcp(&self) -> bool;
        fn is_udp(&self) -> bool;

        fn is_from_client(&self) -> bool;
        fn is_from_server(&self) -> bool;
        fn is_from_client_originally(&self) -> bool;
        fn is_from_server_originally(&self) -> bool;

        #[namespace = "xsnort"]
        fn packet_databuf(pkt: &Packet) -> *const u8;
        #[namespace = "xsnort"]
        fn packet_datalen(pkt: &Packet) -> u16;
    }
}

#[derive(Debug)]
pub struct Packet {
    pkt: *const ffi::Packet,
}

#[derive(Debug)]
pub enum Direction {
    FromClient,
    FromServer,
}

#[derive(Debug)]
pub enum Layer4 {
    Tcp(),
    Udp(),
}

use std::ffi::CStr;
use std::slice;

impl Packet {
    pub fn new(pkt: *const ffi::Packet) -> Packet {
        Packet { pkt }
    }

    pub fn has_ip(&self) -> bool {
        unsafe { self.pkt.as_ref() }.expect("cannot deref").has_ip()
    }

    pub fn direction(&self) -> Direction {
        let ptr = unsafe { self.pkt.as_ref() }.expect("cannot deref");
        if ptr.is_from_client() {
            Direction::FromClient
        } else {
            Direction::FromServer
        }
    }

    pub fn l4(&self) -> Layer4 {
        if self.is_udp() {
            Layer4::Udp()
        } else {
            Layer4::Tcp()
        }
    }

    pub fn payload(&self) -> &[u8] {
        let ptr = unsafe { self.pkt.as_ref() }.expect("cannot deref");
        let len: usize = ffi::packet_datalen(ptr).into();
        unsafe { slice::from_raw_parts(ffi::packet_databuf(ptr), len) }
    }

    pub fn is_from_client_originally(&self) -> bool {
        unsafe { self.pkt.as_ref() }
            .expect("cannot deref")
            .is_from_client_originally()
    }
    pub fn is_tcp(&self) -> bool {
        unsafe { self.pkt.as_ref() }.expect("cannot deref").is_tcp()
    }

    pub fn is_udp(&self) -> bool {
        unsafe { self.pkt.as_ref() }.expect("cannot deref").is_udp()
    }

    pub fn get_type(&self) -> &str {
        let tp = unsafe { CStr::from_ptr(self.pkt.as_ref().expect("cannot deref").get_type()) };
        tp.to_str().expect("invalid type")
    }
}
