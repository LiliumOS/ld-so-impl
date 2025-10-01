use core::ffi::c_void;

unsafe extern "C" {
    pub safe static _plt_resolve_sym_impl: c_void;
}

pub const WORD_RELOC: u32 = 1;
pub const JUMP_SLOT_RELOC: u32 = 7;
pub const GLOB_DAT_RELOC: u32 = 6;
pub const RELATIVE_RELOC: u32 = 8;

pub const TPOFF_RELOC: u32 = 18;
pub const DTPMOD_RELOC: u32 = 16;
pub const DTPOFF_RELOC: u32 = 17;
