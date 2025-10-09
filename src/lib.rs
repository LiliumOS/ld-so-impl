#![no_std]
#![no_builtins] // builtins can include a plt call which is uh... a problem
#![feature(
    sync_unsafe_cell,
    array_ptr_get,
    cstr_bytes,
    macro_metavar_expr,
    slice_from_ptr_range,
    str_from_raw_parts
)]
#![cfg_attr(feature = "alloc", feature(allocator_api))]

use core::ffi::c_void;

use crate::elf::{DynEntryType, ElfDyn};

#[cfg(feature = "alloc")]
extern crate alloc;

mod debug;

#[cfg(feature = "debug")]
pub mod lddebug;

pub mod elf;
pub mod traits;

pub mod helpers;

pub mod loader;
pub mod resolver;

pub mod arch;

#[cfg(feature = "entry")]
pub mod entry;

unsafe extern "C" {
    unsafe static mut _GLOBAL_OFFSET_TABLE_: [*mut c_void; 3];
    safe static _DYNAMIC: [ElfDyn; 4];
}

hidden_syms!(_GLOBAL_OFFSET_TABLE_, _DYNAMIC);

/// Gets the load address of the current module (usually the dynamic linker).
#[inline]
pub fn load_addr() -> *mut c_void {
    let dyn_offset = unsafe { safe_addr_of!(_GLOBAL_OFFSET_TABLE_).cast::<usize>().read() };
    let dyn_addr = safe_addr_of!(_DYNAMIC).cast::<c_void>().cast_mut();

    dyn_addr.wrapping_byte_sub(dyn_offset)
}

// Helper function for obtaining the entire dynamic section of the current module (usually the dynamic linker).
#[inline]
pub fn dynamic_section() -> &'static [ElfDyn] {
    let begin = safe_addr_of!(_DYNAMIC).cast::<ElfDyn>();
    let mut end = begin;
    while unsafe { (*end).d_tag } != DynEntryType::DT_NULL {
        end = unsafe { end.add(1) };
    }
    unsafe { core::slice::from_ptr_range(begin..end) }
}
