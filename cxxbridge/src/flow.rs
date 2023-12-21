#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("flow/flow.h");
        include!("flow.cc");

        #[namespace = "snort"]
        pub type Flow;

//        fn has_ip(&self) -> bool;

//        #[namespace = "xsnort"]
//        fn packet_databuf(pkt: &Packet) -> *const u8;
    }
}

#[derive(Debug)]
pub struct Flow {
    _flow: *const ffi::Flow,
}


impl Flow {
    pub fn new(flow: *const ffi::Flow) -> Flow {
        Flow { _flow: flow }
    }

    pub fn get_service(&self) -> &str {
        //let ptr = unsafe { self.flow.as_ref() }.expect("cannot deref");
        //unsafe { CStr::from_ptr(get_service(flow)) }.to_str().expect("invalid service");
        "todo"
    }



}
