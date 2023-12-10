use std::pin::Pin;

#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("protocols/packet.h");

        #[namespace = "snort"]
        type Packet;
    }

    extern "Rust" {
        fn eval_packet(pkt: Pin<&mut Packet>);
    }
}

use crate::ffi::Packet;

pub fn eval_packet(_pkt: Pin<&mut Packet>) {
    println!("machinery in place!");
}

// Callbacks from the snort glue code

/*
#[no_mangle]
pub extern "C" fn snortEval(packet: SnortPacket) {
    let type_name = packet.get_type().into_string();
    println!("** {type_name:#?}");

    if packet.has_ip() {
        /*
        let src_ip = packet.get_src_ip();
        let dst_ip = packet.get_dst_ip();
        println!("** {type_name}: {src_ip} -> {dst_ip}");
        */
    } else {
        println!("** packet is not IP based");
    }
}

// Definition of SnortPacket type, and Packet trait w. implementation for SnortPacket
type SnortPacket = *const std::ffi::c_void;

pub trait Packet {
    fn get_type(&self) -> CString; // Returns a string like "UPD", "TCP", ... for the type of the packet
    fn has_ip(&self) -> bool; // Returns true if packet is IP based, otherwise returns false
                              /*
                              fn get_src_ip(&self) -> String; // Returns a string with the src addr (only valid if has_ip returns true)
                              fn get_dst_ip(&self) -> String; // Returns a string with the dst addr (only valid if has_ip returns true)
                              */
}

impl Packet for SnortPacket {
    fn get_type(&self) -> CString {
        CString::from(unsafe { CStr::from_ptr(getType(*self)) })
    }

    fn has_ip(&self) -> bool {
        unsafe { hasIp(*self) }
    }

    /*
    fn get_src_ip(&self) -> CString {
            let mut buffer: std::vec::Vec<u8> = std::vec::Vec::new();
            buffer.resize(getMaxIpLen(), 0);
        unsafe {
            getSrcIp(*self, buffer.as_mut_ptr(), buffer.len());
            conv_cstring(buffer.as_ptr())
        }
    }

    fn get_dst_ip(&self) -> CString {
        unsafe {
            let mut buffer: std::vec::Vec<u8> = std::vec::Vec::new();
            buffer.resize(getMaxIpLen(), 0);
            getDstIp(*self, buffer.as_mut_ptr(), buffer.len());
            conv_cstring(buffer.as_ptr())
        }
    }
    */
}

// Prototypes for calls to snort plugin glue code
extern "C" {
    fn getType(packet: SnortPacket) -> *const c_char;
    fn hasIp(packet: SnortPacket) -> bool;

    fn getMaxIpLen() -> usize; // Returns min lenght for the string that must be given to below functions
    fn getSrcIp(packet: SnortPacket, srcData: *mut c_char, srcLen: usize);
    fn getDstIp(packet: SnortPacket, srcData: *mut c_char, srcLen: usize);
}

// Export functions for module setup

#[no_mangle]
pub extern "C" fn getModuleName() -> *const u8 {
    assert!(MODULE_NAME.ends_with("\0"));
    MODULE_NAME.as_ptr()
}

#[no_mangle]
pub extern "C" fn getModuleHelpText() -> *const u8 {
    assert!(MODULE_HELP_TEXT.ends_with("\0"));
    MODULE_HELP_TEXT.as_ptr()
}

// Helper functions for type conversion between C and Rust

fn conv_cstring(in_str: *const c_char) -> CString {
    let cs = unsafe { CStr::from_ptr(in_str) };
    CString::from(cs)
}
*/
