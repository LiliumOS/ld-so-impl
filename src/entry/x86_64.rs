use core::ffi::{c_char, c_void};

use crate::entry::FiniTag;

#[unsafe(naked)]
pub unsafe extern "sysv64" fn __call_entry_point<F: FiniTag>(
    argc: usize,            /* rdi */
    argv: *mut *mut c_char, /* rsi */
    envp: *mut *mut c_char, /* rdx */
    numenv: usize,          /* rcx */
    auxv: *mut c_void,      /* r8 */
    numaux: usize,          /* r9 */
    entry: *const c_void,   /* rsp[-8] */
) -> ! {
    core::arch::naked_asm! {
        "pop rax",
        "pop r10",
        "mov r11, rdi",
        "add r11, rcx",
        "test r11, 1",
        "je 2f",
        "push rax",
        // Setup auxv
        "2:",
        "shl rcx, 3",
        "shl r9, 4",
        "push 0", // alignment
        "push 0", // AT_END
        "sub rsp, r9",
        "2:",
        "test r9, r9",
        "je 3f",
        "lea r9, [r9-16]",
        "movups xmm0, xmmword ptr [r8+r9]",
        "movups xmmword ptr [rsp+r9], xmm0",
        "jmp 2b",

        "3:",
        "mov rbx, rsp",
        // env
        "push 0",
        "2:",
        "test rcx, rcx",
        "je 3f",
        "lea rcx, [rcx-8]",
        "push qword ptr [rdx+rcx]",
        "jmp 2b",
        "3:",
        "mov r12, rsp",
        // argv
        "push 0",
        "mov rcx, rdi",
        "2:",
        "test rcx, rcx",
        "je 2f",
        "lea rcx, [rcx-1]",
        "push qword ptr [rsi+rcx*8]",
        "jmp 2b",
        "2:",
        // argc
        "push rdi",
        "mov rax, 1",
        "lea rdx, [{_local_fini}+rip]",
        "jmp r10",
        _local_fini = sym <F as FiniTag>::fini
    }
}
