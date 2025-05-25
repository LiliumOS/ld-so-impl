use core::ffi::{CStr, c_char};

use bytemuck::{PodInOption, ZeroableInOption};

pub trait CStrExt {
    unsafe fn to_str_unchecked(&self) -> &str;
}

impl CStrExt for CStr {
    unsafe fn to_str_unchecked(&self) -> &str {
        unsafe { core::str::from_utf8_unchecked(self.to_bytes()) }
    }
}

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

#[repr(transparent)]
#[derive(Copy, Clone, Hash, PartialEq, Eq)]
pub struct NamePtr(core::ptr::NonNull<c_char>);

impl core::ops::Deref for NamePtr {
    type Target = CStr;

    fn deref(&self) -> &Self::Target {
        unsafe { cstr_from_ptr(self.0.as_ptr()) }
    }
}

unsafe impl ZeroableInOption for NamePtr {}

impl NamePtr {
    pub const unsafe fn new_unchecked(ptr: core::ptr::NonNull<c_char>) -> Self {
        Self(ptr)
    }
}

impl core::fmt::Debug for NamePtr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let str = &**self;

        str.fmt(f)
    }
}
