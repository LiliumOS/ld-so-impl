use core::ffi::{CStr, c_char};

#[unsafe(export_name = "strlen")]
pub unsafe extern "C" fn strlen_impl(p: *const c_char) -> usize {
    let mut len = 0;
    while unsafe { p.add(len).read() } != 0 {
        len += 1;
    }
    len
}

#[inline(always)]
pub unsafe fn cstr_from_ptr<'a>(p: *const c_char) -> &'a CStr {
    let len = unsafe { crate::safe_call!(unsafe fn strlen_impl { p }) };

    unsafe { CStr::from_bytes_with_nul_unchecked(core::slice::from_raw_parts(p.cast(), len + 1)) }
}

#[macro_export]
macro_rules! hidden_syms{
    ($($name:ident),* $(,)?) => {
        ::core::arch::global_asm!{
            $(::core::concat!(".hidden {", ::core::stringify!($name), "}"),)*
            $($name = sym $name),*
        }
    };
}

hidden_syms! {
    strlen_impl,
}
