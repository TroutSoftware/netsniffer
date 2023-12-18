#[cxx::bridge]
pub mod ffi {
    /*
    unsafe extern "C++" {
        include!("flow/flow.h");

        #[namespace = "snort"]
        type Flow;
    }

    unsafe extern "C++" {
        include!("x_flow.h");

        #[namespace = "xsnort"]
        fn get_service(flow: &Flow) -> *const c_char;
    }

    unsafe extern "C++" {
        include!("framework/data_bus.h");
        include!("cxxbridge.in.h");

        #[namespace = "snort"]
        type DataEvent;
        // #[namespace = "xsnort"]
        // fn event_get_ip(e: &DataEvent) -> *const crate::ffi::SfIp;
    }
    */
}

pub mod snort {
    pub struct DataEvent;

    impl DataEvent {}
}

pub mod packet;
pub mod sfip;
