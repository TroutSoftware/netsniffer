pub fn add(left: usize, right: usize) -> usize {
    left + right
}

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
