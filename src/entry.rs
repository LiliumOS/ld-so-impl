pub trait FiniTag {
    unsafe extern "C" fn fini();
}

impl FiniTag for () {
    unsafe extern "C" fn fini() {}
}

#[cfg_attr(target_arch = "x86_64", path = "entry/x86_64.rs")]
#[cfg_attr(target_arch = "x86", path = "entry/x86.rs")]
mod imp;

pub use imp::*;
