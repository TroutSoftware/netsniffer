#[cxx::bridge]
pub mod ffi {

    unsafe extern "C++" {
        include!("framework/data_bus.h");
        include!("data_event.cc");

        #[namespace = "snort"]
        pub type DataEvent;

//        fn has_ip(&self) -> bool;

//        #[namespace = "xsnort"]
//        fn packet_databuf(pkt: &Packet) -> *const u8;
    }
}

#[derive(Debug)]
pub struct DataEvent {
    _event: *const ffi::DataEvent,
}


impl DataEvent {
    pub fn new(event: *const ffi::DataEvent) -> DataEvent {
        DataEvent { _event : event }
    }

//    pub fn has_ip(&self) -> bool {
//        unsafe { self.pkt.as_ref() }.expect("cannot deref").has_ip()
//    }



}
