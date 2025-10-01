#[doc(hidden)]
#[macro_export]
#[cfg(target_arch = "x86_64")]
macro_rules! get_sym_addr_pcrel {
    ($e:ident => $sym:path) => {
        #[allow(unused_unsafe)]
        unsafe { $crate::helpers::_core::arch::asm!("lea {out}, [{SYM}+rip]", out = out(reg) $e, SYM = sym $sym, options(nomem, pure, nostack));}
    };
}

#[doc(hidden)]
#[macro_export]
#[cfg(target_arch = "x86")]
macro_rules! get_sym_addr_pcrel {
    ($e:ident => $sym:path) => {
        #[allow(unused_unsafe)]
        unsafe { $crate::helpers::_core::arch::asm!("call {get_pc_thunk}", "2:", "add eax, {SYM}-2b", out("eax") $e, SYM = sym $sym, get_pc_thunk = sym $crate::arch::__x86_get_pc_thunk, options(nomem, pure)) }
    };
}

#[macro_export]
macro_rules! safe_addr_of {
    ($sym:path) => {{
        let __p;
        $crate::get_sym_addr_pcrel!(__p => $sym);

        let __p = if false { &raw const $sym } else { __p };
        #[allow(unused_unsafe)]
        unsafe {
            $crate::helpers::_core::hint::assert_unchecked(!__p.is_null() && __p.is_aligned());
        }
        __p
    }};
}

#[macro_export]
macro_rules! safe_addr_of_mut {
    ($sym:path) => {{
        let __p;
        $crate::get_sym_addr_pcrel!(__p => $sym);

        let __p = if false { &raw mut $sym } else { __p };
        #[allow(unused_unsafe)]
        unsafe {
            $crate::helpers::_core::hint::assert_unchecked(!__p.is_null() && __p.is_aligned());
        }
        __p
    }};
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#[inline(always)]
#[cold]
pub fn crash_unrecoverably() -> ! {
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

#[cfg(target_arch = "x86")]
#[doc(hidden)]
#[unsafe(naked)]
pub extern "C" fn __x86_get_pc_thunk() -> *mut core::ffi::c_void {
    core::arch::naked_asm!("lea eax, [esp]", "ret")
}
