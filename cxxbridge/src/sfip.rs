use std::ffi::CString;

#[cxx::bridge]
pub mod ffi {
    extern "Rust" {}

    #[namespace = "snort"]
    unsafe extern "C++" {
        include!("sfip/sf_ip.h");
        include!("sfip.cc");

        #[namespace = "xsnort"]
        unsafe fn from_str(src: *const c_char) -> *const SfIp;
        // TODO(rdo) drop

        type SfIp;
        unsafe fn sfip_ntop(ip: *const SfIp, buf: *mut c_char, bufsize: i32) -> *const c_char;
    }
}

pub struct IP {
    sfip: *const ffi::SfIp,
}

impl IP {
    pub fn new(addr: &str) -> IP {
        let sp = CString::new(addr).expect("cannot access address");
        let sfip = unsafe { ffi::from_str(sp.into_raw()) };
        IP { sfip: sfip }
    }

    pub fn to_str(&self) -> String {
        const MAX_IPV6LEN: usize = 46; // POSIX def
        unsafe {
            let sp = CString::from_vec_unchecked(Vec::with_capacity(MAX_IPV6LEN));
            let raw = sp.into_raw();
            ffi::sfip_ntop(self.sfip, raw, MAX_IPV6LEN.try_into().unwrap());
            return CString::from_raw(raw)
                .into_string()
                .expect("invalid format");
        }
    }
}
