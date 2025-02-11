use core::{arch::global_asm, ffi::c_void};

use crate::elf::{ElfRela, ElfRelocation};

use super::DynEntry;

pub const JUMP_SLOT_RELOC: u64 = 7;
pub const GLOB_DAT_RELOC: u64 = 6;
pub const RELATIVE_RELOC: u64 = 8;

unsafe extern "C" {
    pub safe static _plt_resolve_sym_impl: c_void;
}

global_asm! {
    ".hidden _plt_resolve_sym_impl",
    "_plt_resolve_sym_impl:",
    "pop r11",
    "push rdi",
    "mov rdi, qword ptr [rsp+8]",
    "push rsi",
    "mov rsi, r11",
    "push rdx",
    "push rcx",
    "push r8",
    "push r9",
    "push r10",
    "mov qword ptr [rsp+8], rax",
    "mov r11, qword ptr [rdi+{dyn_ent_jmp_rel_tab}]",
    "lea rdi, [2*rdi+rdi]",
    "lea rdi, [8*rdi+r11]",
    "call {sym_lookup}",
    "mov r11, rax",
    "pop r10",
    "pop r9",
    "pop r8",
    "pop rcx",
    "pop rdx",
    "pop rsi",
    "pop rdi",
    "pop rax",
    "jmp r11",
    sym_lookup = sym plt_resolve_sym,
    dyn_ent_jmp_rel_tab = const const {core::mem::offset_of!(DynEntry, plt_rela) }
}

pub unsafe extern "sysv64" fn plt_resolve_sym(reloc: &ElfRela, dyn_ent: &DynEntry) -> *mut c_void {
    let resolver = unsafe { dyn_ent.resolver.unwrap_unchecked() };
    let sym = reloc.symbol() as usize;
    let offset = reloc.at_offset();

    let name = super::get_sym_name(dyn_ent, sym);

    let addend = reloc.addend();

    let addr = resolver.find_sym(name);

    if addr.is_null() {
        resolver.resolve_error(name);
    }

    let addr = unsafe { addr.offset(addend as isize) };

    let got_ent: *mut *mut c_void = unsafe { dyn_ent.base.add(offset as usize).cast() };

    unsafe {
        got_ent.write(addr);
    }

    addr
}
