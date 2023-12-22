use std::ffi::CStr;

#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("flow/flow.h");
        include!("flow.cc");

        #[namespace = "snort"]
        pub type Flow;

//        fn has_ip(&self) -> bool;

        #[namespace = "xsnort"]
        fn flow_service(flow: &Flow) -> *const c_char;


    }
}

#[derive(Debug)]
pub struct Flow {
    flow: *const ffi::Flow,
}


impl Flow {
    pub fn new(flow: *const ffi::Flow) -> Flow {
        Flow { flow: flow }
    }

    pub fn get_service(&self) -> &str {
        let ptr = unsafe { self.flow.as_ref() }.expect("cannot deref");
        let sname = unsafe { CStr::from_ptr(ffi::flow_service(ptr))};

        sname.to_str().expect("invalid type")
    }



}
