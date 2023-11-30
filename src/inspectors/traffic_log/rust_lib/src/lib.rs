// Copyright (c) Trout Software 2023

// Modify the next two statics to set the module name, and help text for snort
// NOTE: Strings must be 0 terminated, as they are transfered unmodified by snort which expects zero terminated, c-style strings

/// cbindgen:ignore
static MODULE_NAME:      &'static str = "trafic_log\0";
/// cbindgen:ignore
static MODULE_HELP_TEXT: &'static str = "trafic_log logging network trafic\0";

// Callbacks from the snort glue code
#[no_mangle]
pub extern "C" fn snortEval(packet: SnortPacket) {
    println!("**Rust got packet");
    let type_name = packet.get_type();
    println!("**  type is: {type_name}");
    if packet.has_ip() {
        let src_ip = packet.get_src_ip();
        println!("**  Src IP: {src_ip}");
        let dst_ip = packet.get_dst_ip();
        println!("**  Src IP: {dst_ip}");

    } else {
        println!("**  packet is not IP based");
    }
}


// Definition of SnortPacket type, and Packet trait w. implementation for SnortPacket
type SnortPacket = *const std::ffi::c_void;

pub trait Packet {
    fn get_type(&self) -> String;   // Returns a string like "UPD", "TCP", ... for the type of the packet
    fn has_ip(&self) -> bool;       // Returns true if packet is IP based, otherwise returns false
    fn get_src_ip(&self) -> String;   // Returns a string with the src addr (only valid if has_ip returns true)
    fn get_dst_ip(&self) -> String;   // Returns a string with the dst addr (only valid if has_ip returns true)
}

impl Packet for SnortPacket {
    fn get_type(&self) -> String {                
        unsafe {
            conv_cstring(getType(*self))
        }        
    }

    fn has_ip(&self) -> bool {
        unsafe {
            hasIp(*self)
        }
    }

    fn get_src_ip(&self) -> String {
        unsafe {
            let mut buffer: std::vec::Vec<u8> = std::vec::Vec::new();
            buffer.resize(getMaxIpLen(), 0);
            getSrcIp(*self, buffer.as_mut_ptr(), buffer.len());
            conv_cstring(buffer.as_ptr())
        }
    }

    fn get_dst_ip(&self) -> String {
        unsafe {
            let mut buffer: std::vec::Vec<u8> = std::vec::Vec::new();
            buffer.resize(getMaxIpLen(), 0);
            getDstIp(*self, buffer.as_mut_ptr(), buffer.len());
            conv_cstring(buffer.as_ptr())
        }
    }

}

// Prototypes for calls to snort plugin glue code
extern "C" {
    fn getType(packet: SnortPacket) -> *const u8;   
    fn hasIp(packet: SnortPacket) -> bool;
    
    fn getMaxIpLen() -> usize;  // Returns min lenght for the string that must be given to below functions
    fn getSrcIp(packet: SnortPacket, srcData: *mut u8, srcLen: usize);
    fn getDstIp(packet: SnortPacket, srcData: *mut u8, srcLen: usize);
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

fn conv_cstring(in_str: *const u8) -> String {
    unsafe {
            let mut count = 0;

            while *in_str.offset(count) != 0 {
                count += 1;
            }

            let out_slice = std::ptr::slice_from_raw_parts(in_str, usize::try_from(count).unwrap());
            
            std::str::from_utf8(&*out_slice).unwrap().to_string()
    }
}


//////////////////////// END OF USEFULL CONTENT ////////////////////////


/*
type SnortPackage = std::ffi::c_void;

trait Package {    
    extern "C" fn eval(&self);
}

impl Package for *const SnortPackage {
    #[no_mangle]
    extern "C" fn eval(&self) {
        println!("Snort got package");
    }
}
*/
/*
impl SnortPackage {
    #[no_mangle]
    pub extern "C" fn eval(&self) {
        println!("Snort got package");
    }
}
*/

//// vvvv //// OLD DEPRECATED CODE BELOW //// vvvv ////

#[no_mangle]
pub extern "C" fn rust_init() {
    println!("This is rust code!");
}

#[no_mangle]
pub extern "C" fn rust_add(a: i32, b: i32) -> i32 {
    a+b
}

#[no_mangle]
pub extern "C" fn rust_pkg(len: u32, pkt: *const u8) {
    // Process the package, we are in unsafe land when touching pointers directly
    unsafe {
        process_pkg(std::slice::from_raw_parts(pkt, len.try_into().unwrap()));
    }
}



#[no_mangle]
pub extern "C" fn rust_payload(size: u16, data: *const u8) {
    // Process the payload of the package

    println!("Payload size is {size} bytes");
    unsafe {
        process_data(std::slice::from_raw_parts(data, size.try_into().unwrap()));
    }
}



// Safe rust code
fn process_pkg(_data: &[u8]) {
    println!("Rust got new package:");

    //for (i, &byte) in data.iter().enumerate() {
    //    println!("mkr [{i}]='{byte}'");
    //}
    println!("---------------------");
}

fn process_data(data: &[u8]) {
    println!("Rust got new payload:");

    //for (i, &byte) in data.iter().enumerate() {
    //    println!("mkr [{i}]='{byte}'");
    //}

    let version = data[0];
    let ptype = data[1];
    println!("Version: {version}");
    println!("Type: {ptype}");
    
    println!("---------------------");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
