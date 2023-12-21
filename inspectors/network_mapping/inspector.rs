


#[cxx::bridge]
mod ffi {

    extern "C++" {
        include!("protocols/packet.h");
        include!("framework/data_bus.h");
        #[namespace = "snort"]
        type Packet = cxxbridge::packet::ffi::Packet;
        #[namespace = "snort"]
        type Flow = cxxbridge::flow::ffi::Flow;
        #[namespace = "snort"]
        type DataEvent = cxxbridge::data_event::ffi::DataEvent;
    }

    extern "Rust" {
        fn eval_packet(pkt: &Packet);
        fn handle_event(_evt: &DataEvent, flow: &Flow);
        unsafe fn set_log_file(name: *const c_char);
    }
}

use cxxbridge::data_event::DataEvent;
use cxxbridge::flow::Flow;
use cxxbridge::packet::Packet;

//use cxxbridge::ffi::get_service;
use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::raw::c_char;
use std::sync::{Mutex, OnceLock};



pub struct LogFile {
    file_name: String,
    file_handle: Option<File>,
}

impl Default for LogFile {
    fn default() -> Self {
        Self {
            file_name: String::from(""),
            file_handle: None,
        }
    }
}

impl LogFile {
    pub fn set_file_name(&mut self, name: String) {
        match self.file_handle {
            None => self.file_name = name,
            Some(_) => panic!("Can't rename logfile after use"),
        }
    }

    pub fn handle(&mut self) -> &File {
        match (&self.file_handle, self.file_name.is_empty()) {
            (Some(_), _) =>  {},
            (None, true) => panic!("No log file name given"),
            (None, false) =>
                self.file_handle = Some(OpenOptions::new().append(true).create(true).open(&self.file_name).ok().expect("Can't create or open file")),
        }
        self.file_handle.as_mut().unwrap()
    }
}

fn log_file() -> &'static Mutex<LogFile> {
    static LOG_FILE: OnceLock<Mutex<LogFile>> = OnceLock::new();
    LOG_FILE.get_or_init(|| Mutex::new(LogFile::default()))
}

pub fn eval_packet(org_pkt: &cxxbridge::packet::ffi::Packet) {
    let pkt = Packet::new(org_pkt);
    let client_orig = pkt.is_from_client_originally();
    let has_ip = pkt.has_ip();
    let of_type = pkt.get_type();
    let tcp = pkt.is_tcp();

    writeln!(log_file().lock().unwrap().handle(), "machinery in place {client_orig}, {has_ip}, {tcp} {of_type}").ok();

}

pub fn handle_event(evt: &cxxbridge::data_event::ffi::DataEvent, org_flow: &cxxbridge::flow::ffi::Flow) {
    let flow = Flow::new(org_flow);
    //let nm = unsafe { CStr::from_ptr(get_service(flow)) }
    //    .to_str()
    //    .expect("invalid service");
    let nm = flow.get_service();
    println!("service name is {nm}");
}

pub unsafe fn set_log_file(name: *const c_char) {
    let log_file_name = CStr::from_ptr(name)
        .to_str()
        .expect("invalid results from Snort");

    log_file().lock().unwrap().set_file_name(log_file_name.to_string());
}
