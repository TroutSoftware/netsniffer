#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("protocols/packet.h");

        #[namespace = "snort"]
        pub type Packet;

        fn is_from_client_originally(&self) -> bool;
        fn has_ip(&self) -> bool;
        fn get_type(&self) -> *const c_char;
        fn is_tcp(&self) -> bool;
    }
}

#[derive(Debug)]
pub struct Packet {
    pkt: *const ffi::Packet,
}

use std::ffi::CStr;

impl Packet {
    pub fn new(pkt: *const ffi::Packet) -> Packet {
        Packet { pkt }
    }

    pub fn has_ip(&self) -> bool {
        unsafe { self.pkt.as_ref() }.expect("cannot deref").has_ip()
    }
    pub fn is_from_client_originally(&self) -> bool {
        unsafe { self.pkt.as_ref() }
            .expect("cannot deref")
            .is_from_client_originally()
    }
    pub fn is_tcp(&self) -> bool {
        unsafe { self.pkt.as_ref() }.expect("cannot deref").is_tcp()
    }

    pub fn get_type(&self) -> &str {
        let tp = unsafe { CStr::from_ptr(self.pkt.as_ref().expect("cannot deref").get_type()) };
        tp.to_str().expect("invalid type")
    }
}
