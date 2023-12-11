#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("protocols/packet.h");

        #[namespace = "snort"]
        type Packet;

        fn is_from_client_originally(&self) -> bool;
        fn has_ip(&self) -> bool;
        fn get_type(&self) -> *const c_char;
        fn is_tcp(&self) -> bool;
    }

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

        #[namespace = "snort"]
        type DataEvent;
    }
}
