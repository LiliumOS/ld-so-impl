#[macro_export]
#[cfg(target_arch = "x86_64")]
/// Takes the address of a local symbol
macro_rules! safe_addr_of {
    ($p:path) => {
        {
            let __r;

            #[allow(unused_unsafe)]
            unsafe{::core::arch::asm!("lea {r}, [{SYM}+rip]", r= out(reg) __r, SYM = sym $p, options(nostack, nomem, pure));}
            let __r = if false {
                &raw const $p
            } else {
                __r
            };
            #[allow(unused_unsafe)]
            unsafe{::core::hint::assert_unchecked((!__r.is_null())&&__r.is_aligned());}
            __r
        }
    }
}

#[macro_export]
#[cfg(target_arch = "x86_64")]
/// Takes the address of a local symbol
macro_rules! safe_addr_of_mut {
    ($p:path) => {
        {
            let __r;

            #[allow(unused_unsafe)]
            unsafe{::core::arch::asm!("lea {r}, [{SYM}+rip]", r= out(reg) __r, SYM = sym $p, options(nostack, nomem, pure));}
            let __r = if false {
                &raw mut $p
            } else {
                __r
            };
            #[allow(unused_unsafe)]
            unsafe{::core::hint::assert_unchecked((!__r.is_null())&&__r.is_aligned());}
            __r
        }
    }
}

#[macro_export]
#[cfg(target_arch = "x86_64")]
macro_rules! safe_call {
    ($(unsafe $(@ $_tt:tt)?)? fn $p:path {$($params:expr),* $(,)?}) => {
        {
            let __r: *const ();
            #[allow(unused_unsafe)]
            unsafe{::core::arch::asm!("lea {r}, [{SYM}+rip]", r= out(reg) __r, SYM = sym $p, options(nostack, nomem, pure));}

            let fntpr: $(unsafe $(@ $_tt)?)? extern "C" fn ($(${ignore($params)} _),*) -> _ = if false {
                $p
            } else {
                #[allow(unused_unsafe)]
                unsafe{::core::mem::transmute(__r)}
            };
            fntpr($($params),*)
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[cold]
pub fn crash_unrecoverably() -> ! {
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}
