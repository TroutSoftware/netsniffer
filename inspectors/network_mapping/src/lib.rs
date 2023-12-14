
use cxxbridge::ffi::{get_service, DataEvent, Flow, Packet};
use std::ffi::CStr;
use std::os::raw::c_char;

#[cxx::bridge]
mod ffi {
    #[namespace = "snort"]
    extern "C++" {
        type Packet = cxxbridge::ffi::Packet;
        type Flow = cxxbridge::ffi::Flow;
        type DataEvent = cxxbridge::ffi::DataEvent;
    }

    extern "Rust" {
        fn eval_packet(pkt: &Packet);
        fn handle_event(_evt: &DataEvent, flow: &Flow);
        unsafe fn set_log_file(name: *const c_char);
    }
}


pub fn eval_packet(pkt: &Packet) {
    let client_orig = pkt.is_from_client_originally();
    let has_ip = pkt.has_ip();
    let of_type = unsafe { CStr::from_ptr(pkt.get_type()) }
        .to_str()
        .expect("invalid results from Snort");
    let tcp = pkt.is_tcp();

    println!("machinery in place {client_orig}, {has_ip}, {tcp} {of_type}");
}

pub fn handle_event(_evt: &DataEvent, flow: &Flow) {
    let nm = unsafe { CStr::from_ptr(get_service(flow)) }
        .to_str()
        .expect("invalid service");
    println!("service name is {nm}");



}

pub unsafe fn set_log_file(name: *const c_char) {
    let log_file_name = CStr::from_ptr(name)
    //o_file_name = CStr::from_ptr(name)
        .to_str()
        .expect("invalid results from Snort");
    println!("Log file name is set in rust to {log_file_name}");
}
