use super::FiniTag;
use core::ffi::{c_char, c_void};

#[unsafe(naked)]
pub unsafe extern "fastcall" fn __call_entry_point<F: FiniTag>(
    argc: usize,            /* ecx */
    argv: *mut *mut c_char, /* edx */
    envp: *mut *mut c_char, /* esp[-4] */
    numenv: usize,          /* esp[-8] */
    auxv: *mut c_void,      /* esp[-16] */
    numaux: usize,          /* esp[-20] */
    entry: *const c_void,   /* esp[-24] */
) -> ! {
    core::arch::naked_asm!("ud2")
}
