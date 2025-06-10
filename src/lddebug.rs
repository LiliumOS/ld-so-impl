use core::ffi::{c_char, c_int, c_void};

use bytemuck::Zeroable;

use crate::elf::ElfDyn;

static R_NOTIF: u32 = 0;

#[inline(never)]
pub extern "C-unwind" fn __load_break() {
    unsafe {
        core::ptr::read_volatile(&raw const R_NOTIF);
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, Zeroable)]
pub enum RState {
    Consistent,
    Add,
    Delete,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Zeroable)]
pub struct RDebug {
    pub r_version: c_int,
    pub r_map: *mut LinkMap,
    pub r_brk: Option<extern "C-unwind" fn()>,
    pub r_state: RState,
    pub r_ldbase: *const c_void,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct LinkMap {
    pub l_addr: *const c_void,
    pub l_name: *const c_char,
    pub l_dyn: *const ElfDyn,
    pub l_next: *mut LinkMap,
    pub l_prev: *mut LinkMap,
}
