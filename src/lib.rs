#![no_std]
#![no_builtins] // builtins can include a plt call which is uh... a problem
#![feature(
    sync_unsafe_cell,
    array_ptr_get,
    cstr_bytes,
    macro_metavar_expr,
    slice_from_ptr_range
)]
#![cfg_attr(feature = "alloc", feature(allocator_api))]

#[cfg(feature = "alloc")]
extern crate alloc;

mod debug;
pub mod elf;
pub mod traits;

pub mod helpers;

pub mod loader;
pub mod resolver;

pub mod arch;
