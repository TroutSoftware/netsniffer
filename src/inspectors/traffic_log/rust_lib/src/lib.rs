// Copyright (c) Trout Software 2023

// Modify the next two statics to set the module name, and help text for snort
// NOTE: Strings must be 0 terminated, as they are transfered unmodified by snort which expects zero terminated, c-style strings

/// cbindgen:ignore
static MODULE_NAME:      &'static str = "trafic_log\0";
/// cbindgen:ignore
static MODULE_HELP_TEXT: &'static str = "trafic_log logging network trafic\0";


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

// Callbacks from the snort glue code

type SnortPacket = *const std::ffi::c_void;

pub trait Packet {
    fn get_type(&self) -> String;
}

impl Packet for SnortPacket {
    fn get_type(&self) -> String {
        let result: String;
        
        unsafe {
            let data = getType(*self);
            let mut count = 0;

            while *data.offset(count) != 0 {
                count += 1;
            }

            let type_string = std::ptr::slice_from_raw_parts(data, usize::try_from(count).unwrap());
            
            result = std::str::from_utf8(&*type_string).unwrap().to_string();
        }
        return result
        //format!("unknown {result}")        
    }


}


#[no_mangle]
pub extern "C" fn snortEval(packet: SnortPacket) {
    println!("**Rust got package");
    let type_name = packet.get_type();
    println!("**type is: {type_name}");
}

extern "C" {
    fn getType(packet: SnortPacket) -> *const u8;
}


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
