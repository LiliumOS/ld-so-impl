#![no_std]
#![no_builtins] // builtins can include a plt call which is uh... a problem
#![feature(sync_unsafe_cell, array_ptr_get, cstr_bytes, macro_metavar_expr)]

mod debug;
pub mod elf;
pub mod traits;

pub mod helpers;

pub mod resolver;

pub mod arch;
