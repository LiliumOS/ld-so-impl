use core::{
    cell::{Cell, SyncUnsafeCell},
    ffi::{CStr, c_char, c_void},
    mem::offset_of,
    ptr::NonNull,
    str::FromStr,
    sync::atomic::{AtomicPtr, AtomicUsize, Ordering},
};

use bytemuck::Zeroable;

#[cfg(feature)]
use crate::lddebug::RDebug;
#[cfg(feature = "debug")]
use crate::lddebug::{LinkMap, RDebug};
use crate::{
    arch::crash_unrecoverably,
    elf::{
        DynEntryType, ElfClass, ElfDyn, ElfGnuHashHeader, ElfHeader, ElfPhdr, ElfRela,
        ElfRelocation, ElfSym, ElfSymbol,
        consts::{
            PF_R, PF_W, PF_X, PT_DYNAMIC, PT_GNU_STACK, PT_LOAD, PT_PHDR, PT_TLS, ProgramType,
            STB_WEAK, STT_GNU_IFUNC,
        },
    },
    helpers::{CStrExt, NamePtr, cstr_from_ptr, strlen_impl},
    loader::{Error, LoaderImpl},
    safe_addr_of,
};

#[repr(C, align(64))]
#[derive(Copy, Clone, Zeroable, Debug)]
pub struct DynEntry {
    got: *mut *const c_void,
    pub base: *mut c_void,
    syms: *const ElfSym,
    name: Option<NamePtr>,
    strtab: *const c_char,
    hash: *const u32,
    plt_rela: *const ElfRela,
    plt_relasz: usize,
    resolver: Option<&'static Resolver>,
    gnu_hash: *const ElfGnuHashHeader,
    pub dyn_section: *const ElfDyn,
    pub phdrs: Option<NonNull<ElfPhdr>>,
    pub phdrs_size: usize,

    #[cfg(feature = "tls")]
    tls_module: isize,
    #[cfg(feature = "debug")]
    debug_node: *mut LinkMap,
}

unsafe impl Send for DynEntry {}
unsafe impl Sync for DynEntry {}

bitflags::bitflags! {
    #[derive(bytemuck::Pod, Zeroable, Copy, Clone)]
    #[repr(transparent)]
    pub struct ResolverDebug : u32 {
        const LOADING = 0x0000_0001;
        const DYNAMIC = 0x0000_0002;
        const RELOCATIONS = 0x0000_0004;
        const SYMBOLS = 0x0000_0008;
        const HASH_LOOKUP = 0x0000_0010;
        const LIB_SEARCH = 0x0000_0020;
    }
}

#[derive(Debug)]
pub struct ResolverDebugFromStrError;

impl FromStr for ResolverDebug {
    type Err = ResolverDebugFromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut val = ResolverDebug::empty();
        for v in s.split(',').map(str::trim_ascii) {
            let v = v.trim();
            match v {
                "loading" => val |= ResolverDebug::LOADING,
                "dynamic" => val |= ResolverDebug::DYNAMIC,
                "relocation" => val |= ResolverDebug::RELOCATIONS,
                "symbols" => val |= ResolverDebug::SYMBOLS,
                "hash" => val |= ResolverDebug::HASH_LOOKUP,
                "libs" => val |= ResolverDebug::LIB_SEARCH,
                "1" | "true" | "yes" | "on" | "all" => val |= ResolverDebug::all(),
                "0" | "false" | "no" | "off" | "none" => val |= ResolverDebug::empty(),
                _ => return Err(ResolverDebugFromStrError),
            }
        }

        Ok(val)
    }
}

#[cfg_attr(target_pointer_width = "64", repr(C, align(128)))]
#[cfg_attr(target_pointer_width = "32", repr(C, align(64)))]
struct ResolverHead {
    entry_count: AtomicUsize,
    has_entered_resolve_fn: AtomicUsize,
    cb_resolve_err: Option<fn(&CStr, Error) -> !>,
    loader: Option<&'static (dyn LoaderImpl + Sync)>,
    delegate: Option<&'static Resolver>,
    force_resolve_now: Cell<bool>,
    debug: Cell<ResolverDebug>,
    curr_head: AtomicPtr<Resolver>,
    next: AtomicPtr<Resolver>,
    #[cfg(feature = "debug")]
    r_debug: RDebug,
    #[cfg(feature = "debug")]
    end_node: *mut LinkMap,
}

unsafe impl Sync for ResolverHead {}

const STATIC_RESOLVER_ENTRY_COUNT: usize =
    (8192 - core::mem::size_of::<ResolverHead>()) / core::mem::size_of::<DynEntry>();

pub struct LiveEntries<'a>(core::slice::Iter<'a, DynEntry>, Option<&'a Resolver>);

impl<'a> Iterator for LiveEntries<'a> {
    type Item = &'a DynEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(it) = self.0.next() {
            return Some(it);
        }

        let Some(next) = self.1 else {
            return None;
        };
        *self = next.live_entries();
        self.next()
    }
}

#[repr(C, align(4096))]
pub struct Resolver {
    head: ResolverHead,
    static_entries: SyncUnsafeCell<[DynEntry; STATIC_RESOLVER_ENTRY_COUNT]>,
}

impl core::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Resolver")
    }
}

#[macro_export]
macro_rules! debug_resolver {
    ($flag:expr, $this:expr, $($tt:tt)+) => {
        {
            let mut __this: &$crate::resolver::Resolver = &$this;
            if __this.test_debug_flags($flag) {
                use ::core::fmt::Write;
                let _ = ::core::writeln!(&mut __this, $($tt)*);
            }
        }
    }
}

pub struct ResolveError {}

impl Resolver {
    pub const ZERO: Self = Self {
        head: ResolverHead {
            entry_count: AtomicUsize::new(0),
            has_entered_resolve_fn: AtomicUsize::new(0),
            cb_resolve_err: None,
            loader: None,
            delegate: None,
            force_resolve_now: Cell::new(false),
            debug: Cell::new(bytemuck::zeroed()),
            curr_head: AtomicPtr::new(core::ptr::null_mut()),
            next: AtomicPtr::new(core::ptr::null_mut()),
            #[cfg(feature = "debug")]
            r_debug: bytemuck::zeroed(),
            #[cfg(feature = "debug")]
            end_node: core::ptr::null_mut(),
        },
        static_entries: SyncUnsafeCell::new(bytemuck::zeroed()),
    };

    pub unsafe fn force_resolve_now(&self) {
        self.head.force_resolve_now.set(true);
    }

    pub unsafe fn set_debug(&self, debug: ResolverDebug) {
        self.head.debug.set(debug);
    }

    fn test_debug_flags(&self, debug: ResolverDebug) -> bool {
        self.head.debug.get().contains(debug)
    }

    #[inline(always)]
    pub fn delegate(&mut self, other: &'static Resolver) {
        self.head.delegate = Some(other);
    }

    #[inline(always)]
    pub fn resolve_error(&self, sym: &CStr, e: Error) -> ! {
        match self.head.cb_resolve_err {
            Some(cb_resolve_error)
                if self.head.has_entered_resolve_fn.swap(1, Ordering::Relaxed) == 0 =>
            {
                cb_resolve_error(sym, e)
            }
            _ => crate::arch::crash_unrecoverably(),
        }
    }

    #[inline(always)]
    pub fn set_resolve_error_callback(&mut self, cb_resolve_err: fn(&CStr, Error) -> !) {
        self.head.cb_resolve_err = Some(cb_resolve_err);
    }

    #[inline(always)]
    pub fn set_loader_backend(&mut self, loader: &'static (dyn LoaderImpl + Sync)) {
        self.head.loader = Some(loader);
    }

    #[inline(always)]
    pub fn live_entries(&self) -> LiveEntries {
        let count = self.head.entry_count.load(Ordering::Acquire);
        let entries = self.static_entries.get().as_mut_ptr();

        unsafe {
            LiveEntries(
                core::slice::from_raw_parts(entries, count).iter(),
                self.head.next.load(Ordering::Acquire).as_ref(),
            )
        }
    }

    pub unsafe fn load_from_handle(
        &'static self,
        soname: Option<&'static CStr>,
        udata: *mut c_void,
        fhdl: *mut c_void,
        exec_tls: bool,
    ) -> &'static DynEntry {
        let Some(loader) = self.head.loader else {
            self.resolve_error(soname.unwrap_or(c"<unnamed module>"), Error::Fatal)
        };
        match unsafe { self.load_impl(soname, udata, loader, fhdl, exec_tls) } {
            Ok(e) => e,
            Err(e) => self.resolve_error(soname.unwrap_or(c"<unnamed module>"), e),
        }
    }

    #[inline]
    unsafe fn load_impl(
        &'static self,
        soname: Option<&'static CStr>,
        udata: *mut c_void,
        loader: &'static dyn LoaderImpl,
        fd: *mut c_void,
        exec_tls: bool,
    ) -> Result<&'static DynEntry, Error> {
        use core::fmt::Write as _;
        let mut ehdr: ElfHeader = ElfHeader::zeroed();

        loader.read_offset(0, fd, bytemuck::bytes_of_mut(&mut ehdr))?;

        let ph_off = ehdr.e_phoff;
        let ph_num = ehdr.e_phnum as usize;

        let mut phdrs: [ElfPhdr; 32] = bytemuck::zeroed();

        loader.read_offset(ph_off, fd, bytemuck::cast_slice_mut(&mut phdrs[..ph_num]))?;

        let mut load_segments = &phdrs[..];

        for i in 0..phdrs.len() {
            if phdrs[i].p_type == PT_LOAD {
                load_segments = &phdrs[i..];
                break;
            }
        }
        for i in (0..load_segments.len()).rev() {
            if load_segments[i].p_type == PT_LOAD {
                load_segments = &load_segments[..=i];
                break;
            }
        }

        let dyn_phdr = phdrs
            .iter()
            .find(|phdr| phdr.p_type == PT_DYNAMIC)
            .ok_or(Error::MalformedObject)?;

        let highest_pma = load_segments
            .iter()
            .map(|v| v.p_paddr + v.p_memsz)
            .max()
            .unwrap_or(0);

        if cfg!(feature = "deny-wx") {
            if phdrs.iter().any(|phdr| {
                (phdr.p_flags & (PF_W | PF_X)) == (PF_W | PF_X)
                    && ((phdr.p_type == PT_LOAD) || (phdr.p_type == PT_GNU_STACK))
            }) {
                return Err(Error::WritableText);
            }
        }

        let addr = unsafe { loader.alloc_base_addr(udata, highest_pma)? };

        let addr = unsafe { loader.map_phdrs(load_segments, fd, addr)? };

        let mut tls_module = !0;

        let tls_seg = if cfg!(feature = "tls") {
            phdrs.iter().find(|v| v.p_type == PT_TLS)
        } else {
            None
        };

        if cfg!(feature = "tls") {
            if let Some(phdr) = tls_seg {
                tls_module =
                    loader.alloc_tls(phdr.p_memsz as usize, phdr.p_align as usize, exec_tls)?;
            }
        }

        let pt_phdrs = phdrs.iter().find(|v| v.p_type == PT_PHDR);

        let dyn_addr = addr
            .wrapping_add(dyn_phdr.p_paddr as usize)
            .cast::<ElfDyn>()
            .cast_const();

        let mut end = dyn_addr;

        while unsafe { (*end).d_tag } != DynEntryType::DT_NULL {
            unsafe { end = end.add(1) }
        }

        let dyn_seg = unsafe { core::slice::from_ptr_range(dyn_addr..end) };

        let ent = unsafe {
            self.resolve_object(
                addr,
                dyn_seg,
                soname,
                udata,
                tls_module,
                pt_phdrs.map(|v| {
                    let addr = addr.add(v.p_paddr as usize).cast::<ElfPhdr>();
                    let len = v.p_memsz as usize / core::mem::size_of::<ElfPhdr>();
                    core::slice::from_raw_parts(addr, len)
                }),
            )
        };

        if cfg!(feature = "tls") {
            if let Some(phdr) = tls_seg {
                unsafe {
                    loader.load_tls(
                        tls_module,
                        ent.base.add(phdr.p_paddr as usize),
                        phdr.p_memsz,
                    )?;
                }
            }
        }
        Ok(ent)
    }

    pub unsafe fn load(
        &'static self,
        name: &'static CStr,
        udata: *mut c_void,
        exec_tls: bool,
    ) -> &'static DynEntry {
        let Some(loader) = self.head.loader else {
            self.resolve_error(name, Error::Fatal)
        };

        match unsafe { loader.find(name, udata) }.and_then(|fhdl| {
            let ret = unsafe { self.load_impl(Some(name), udata, loader, fhdl, exec_tls) };
            unsafe {
                loader.close_hdl(fhdl);
            }
            ret
        }) {
            Ok(ent) => ent,
            Err(e) => self.resolve_error(name, e),
        }
    }

    /// Safety:
    ///
    /// base must point to the address of the loaded object, which is a well-formed ELF object for the current platform.
    ///
    /// `dyn_ent` must be a slice of the Dynamic section of the object loaded from `base`.
    /// `resolve_object` must be called from a single thread (but may be concurrent with calls to `find_sym` or invocations of the resolver from the plt)
    #[inline(always)]
    pub unsafe fn resolve_object(
        &'static self,
        base: *mut c_void,
        dyn_ent: &[ElfDyn],
        name: Option<&'static CStr>,
        udata: *mut c_void,
        #[allow(unused_variables)] tls_module: isize,
        phdrs: Option<&'static [ElfPhdr]>,
    ) -> &'static DynEntry {
        use core::fmt::Write as _;
        let mut entry = DynEntry {
            got: core::ptr::null_mut(),
            base,
            syms: core::ptr::null(),
            name: name
                .map(|name| unsafe { NonNull::new_unchecked(name.as_ptr().cast_mut()) })
                .map(|name| unsafe { NamePtr::new_unchecked(name) }),
            strtab: core::ptr::null(),
            hash: core::ptr::null(),
            plt_rela: core::ptr::null(),
            plt_relasz: 0,
            resolver: Some(self),
            gnu_hash: core::ptr::null(),
            dyn_section: dyn_ent.as_ptr(),
            phdrs: phdrs.map(NonNull::from_ref).map(NonNull::cast::<ElfPhdr>),
            phdrs_size: phdrs.map(|v| v.len()).unwrap_or(0),
            #[cfg(feature = "tls")]
            tls_module,
            #[cfg(feature = "debug")]
            debug_node: core::ptr::null_mut(),
        };

        let mut rela = core::ptr::null::<ElfRela>();
        let mut rela_count = 0;

        let mut resolve_now = self.head.force_resolve_now.get();

        let mut init = core::ptr::null::<c_void>();
        let mut init_array = core::ptr::null::<*const c_void>();
        let mut init_arraysz = 0;
        let mut soname_ptr = None;

        for ent in dyn_ent {
            if self.test_debug_flags(ResolverDebug::DYNAMIC) {
                debug_resolver!(ResolverDebug::DYNAMIC, self, "Reading Dynamic Tag {ent:?}");
            }
            match ent.d_tag {
                DynEntryType::DT_SYMTAB => {
                    entry.syms = base.wrapping_add(ent.d_val as usize).cast();
                }
                DynEntryType::DT_HASH => {
                    entry.hash = base.wrapping_add(ent.d_val as usize).cast();
                }
                DynEntryType::DT_GNU_HASH => {
                    entry.gnu_hash = base.wrapping_add(ent.d_val as usize).cast();
                }
                DynEntryType::DT_PLTGOT => {
                    entry.got = base.wrapping_add(ent.d_val as usize).cast();
                }
                DynEntryType::DT_BIND_NOW => {
                    resolve_now = true;
                }
                DynEntryType::DT_STRTAB => {
                    entry.strtab = base.wrapping_add(ent.d_val as usize).cast();
                }
                DynEntryType::DT_FLAGS => {
                    resolve_now |= (ent.d_val & 0x8) != 0;
                }
                DynEntryType::DT_FLAGS_1 => {
                    resolve_now |= (ent.d_val & 1) != 0;
                }
                DynEntryType::DT_RELA => {
                    rela = base.wrapping_add(ent.d_val as usize).cast();
                }
                DynEntryType::DT_RELASZ => {
                    rela_count = ent.d_val as usize / core::mem::size_of::<ElfRela>();
                }
                DynEntryType::DT_RELAENT => {
                    if ent.d_val as usize != core::mem::size_of::<ElfRela>() {
                        let _ = writeln!(
                            { self },
                            "Bad relaent. Expected {}, got {}",
                            core::mem::size_of::<ElfRela>(),
                            ent.d_val
                        );
                        crash_unrecoverably();
                    }
                }
                DynEntryType::DT_JMPREL => {
                    entry.plt_rela = base.wrapping_add(ent.d_val as usize).cast();
                }
                // DynEntryType::DT_PLTREL => {
                //     if ent.d_val != DynEntryType::DT_RELA {
                //         let _ = writeln!(
                //             { self },
                //             "Bad relaent. Expected {}, got {}",
                //             DynEntryType::DT_RELA,
                //             ent.d_val
                //         );
                //         crash_unrecoverably();
                //     }
                // }
                DynEntryType::DT_PLTRELSZ => {
                    entry.plt_relasz = ent.d_val as usize / core::mem::size_of::<ElfRela>();
                }
                DynEntryType::DT_INIT => {
                    init = base.wrapping_add(ent.d_val as usize).cast();
                }
                DynEntryType::DT_INIT_ARRAY => {
                    init_array = base.wrapping_add(ent.d_val as usize).cast();
                }
                DynEntryType::DT_INIT_ARRAYSZ => {
                    init_arraysz = ent.d_val as usize / core::mem::size_of::<*const c_void>();
                }
                DynEntryType::DT_SONAME => {
                    soname_ptr = Some(ent.d_val as usize);
                }
                _ => {}
            }
        }

        if entry.name.is_none() {
            entry.name = soname_ptr.map(|v| unsafe {
                NamePtr::new_unchecked(NonNull::new_unchecked(entry.strtab.add(v).cast_mut()))
            });
        }

        let mut entry_list = unsafe {
            self.head
                .curr_head
                .load(Ordering::Acquire)
                .as_ref()
                .unwrap_or(self)
        };

        let soname = entry.name.as_deref().unwrap_or(c"<unnamed>");

        let mut i = entry_list.head.entry_count.fetch_add(1, Ordering::Relaxed);
        if i > STATIC_RESOLVER_ENTRY_COUNT {
            let Some(loader) = self.head.loader else {
                self.resolve_error(soname, Error::Fatal)
            };
            let next = match loader.allocate_next() {
                Ok(next) => next,
                Err(e) => self.resolve_error(soname, e),
            };
            self.head.curr_head.store(next, Ordering::Release);
            entry_list.head.next.store(next, Ordering::Release);
            entry_list = unsafe { &*next };
            i = 0;
        }
        let ptr = unsafe { entry_list.static_entries.get().cast::<DynEntry>().add(i) };

        if !entry.got.is_null() {
            unsafe { entry.got.add(1).write(ptr.cast()) }
            unsafe {
                entry
                    .got
                    .add(2)
                    .write(safe_addr_of!(arch::_plt_resolve_sym_impl))
            }
        }
        unsafe {
            ptr.write(entry);
        }

        let entry = unsafe { &*ptr };

        for ent in dyn_ent {
            if ent.d_tag == DynEntryType::DT_NEEDED {
                let needed: &CStr = unsafe { cstr_from_ptr(entry.strtab.add(ent.d_val as usize)) };

                if self.is_loaded(needed) {
                    continue;
                }

                unsafe {
                    self.load(needed, udata, false);
                }
            }
        }

        let soname = if let Some(soname) = entry.name {
            unsafe {
                core::str::from_raw_parts(soname.as_ptr().cast(), strlen_impl(soname.as_ptr()))
            }
        } else {
            "<unnamed>"
        };

        if !rela.is_null() {
            let rela = unsafe { core::slice::from_raw_parts(rela, rela_count) };
            for rela in rela {
                match rela.rel_type() {
                    arch::WORD_RELOC | arch::GLOB_DAT_RELOC => {
                        let sym = rela.symbol() as usize;

                        let sym_desc = unsafe { entry.syms.add(sym).read() };
                        let val = if sym_desc.section() != 0
                            && (sym_desc.other() & 3 != 0 || (sym_desc.info() >> 4) == 0)
                        {
                            // local or protected symbol. We know what the address is
                            base.wrapping_add(sym_desc.value() as usize)
                        } else {
                            let name = get_sym_name(entry, sym);

                            debug_resolver!(
                                ResolverDebug::RELOCATIONS,
                                self,
                                "Processing non-local GLOB_DAT relocation against {}...",
                                unsafe { name.to_str_unchecked() }
                            );

                            let val = self.find_sym(name, true);

                            debug_resolver!(
                                ResolverDebug::RELOCATIONS,
                                self,
                                "Found {}: {val:p}",
                                unsafe { name.to_str_unchecked() }
                            );

                            if val.is_null() && (sym_desc.info() >> 4) != 2 {
                                self.resolve_error(name, Error::SymbolNotFound)
                            }
                            val
                        };

                        let addend = rela.addend() as isize;

                        let offset = rela.at_offset() as usize;

                        let slot = unsafe { base.add(offset).cast::<*mut c_void>() };
                        unsafe {
                            slot.write(val.offset(addend));
                        }
                    }
                    arch::RELATIVE_RELOC => {
                        let val = base;

                        let addend = rela.addend() as isize;

                        let offset = rela.at_offset() as usize;

                        let slot = unsafe { base.add(offset).cast::<*mut c_void>() };
                        unsafe {
                            slot.write(val.offset(addend));
                        }
                    }
                    #[cfg(feature = "tls")]
                    arch::TPOFF_RELOC => {
                        let sym = rela.symbol() as usize;

                        let sym_desc = unsafe { entry.syms.add(sym).read() };
                        let name = get_sym_name(entry, sym);

                        let (ent, off): (&DynEntry, usize) = if sym_desc.section() != 0
                            && (sym_desc.other() & 3 != 0 || (sym_desc.info() >> 4) == 0)
                        {
                            // local or protected symbol. We know what the address is
                            (entry, sym_desc.value() as usize + rela.addend() as usize)
                        } else if name == c"" {
                            (entry, rela.addend() as usize)
                        } else {
                            let Some((entry, off)) = self.find_sym_module_offset(name) else {
                                self.resolve_error(name, Error::SymbolNotFound)
                            };
                            (entry, off + rela.addend() as usize)
                        };

                        let module = ent.tls_module;

                        let Some(loader) = self.head.loader else {
                            self.resolve_error(name, Error::Fatal)
                        };

                        let moff = loader
                            .tls_direct_offset(module)
                            .unwrap_or_else(|e| self.resolve_error(name, e)); // Errors if we can't do a `TPOFF` reloc 

                        let val = moff.wrapping_add_unsigned(off);

                        let offset = rela.at_offset() as usize;

                        let slot = unsafe { base.add(offset).cast::<isize>() };
                        unsafe {
                            slot.write(val);
                        }
                    }
                    #[cfg(feature = "tls")]
                    arch::DTPOFF_RELOC => {
                        let sym = rela.symbol() as usize;

                        let sym_desc = unsafe { entry.syms.add(sym).read() };
                        let name = get_sym_name(entry, sym);
                        let (_, off): (&DynEntry, usize) = if sym_desc.section() != 0
                            && (sym_desc.other() & 3 != 0 || (sym_desc.info() >> 4) == 0)
                        {
                            // local or protected symbol. We know what the address is
                            (entry, sym_desc.value() as usize)
                        } else {
                            let Some(val) = self.find_sym_module_offset(name) else {
                                self.resolve_error(name, Error::SymbolNotFound)
                            };
                            val
                        };

                        let val = off;

                        let offset = rela.at_offset() as usize;

                        let slot = unsafe { base.add(offset).cast::<usize>() };
                        unsafe {
                            slot.write(val);
                        }
                    }
                    #[cfg(feature = "tls")]
                    arch::DTPMOD_RELOC => {
                        let sym = rela.symbol() as usize;
                        let name = get_sym_name(entry, sym);
                        let sym_desc = unsafe { entry.syms.add(sym).read() };
                        let (ent, _): (&DynEntry, usize) = if sym == 0
                            || (sym_desc.section() != 0
                                && (sym_desc.other() & 3 != 0 || (sym_desc.info() >> 4) == 0))
                        {
                            // local or protected symbol. We know what the address is
                            (entry, sym_desc.value() as usize)
                        } else {
                            let Some(val) = self.find_sym_module_offset(name) else {
                                self.resolve_error(name, Error::SymbolNotFound)
                            };
                            val
                        };

                        let module = ent.tls_module;

                        let val = module;

                        let offset = rela.at_offset() as usize;

                        let slot = unsafe { base.add(offset).cast::<isize>() };
                        unsafe {
                            slot.write(val);
                        }
                    }
                    x => {
                        if let Some(mut loader) = self.head.loader {
                            use core::fmt::Write as _;
                            let _ = writeln!(loader, "{soname}: Unexpected relocation type {x}");
                        }
                    }
                }
            }
        }

        if !entry.plt_rela.is_null() {
            let jumprel: &[ElfRela] =
                unsafe { core::slice::from_raw_parts(entry.plt_rela, entry.plt_relasz) };

            for rela in jumprel {
                match rela.rel_type() {
                    arch::JUMP_SLOT_RELOC if resolve_now => {
                        let sym = rela.symbol() as usize;
                        let name = get_sym_name(entry, sym);
                        debug_resolver!(
                            ResolverDebug::RELOCATIONS,
                            self,
                            "Resolving eager JUMP_SLOT relocation against {}",
                            unsafe { name.to_str_unchecked() }
                        );
                        let offset = rela.at_offset() as usize;

                        let slot = unsafe { base.add(offset).cast::<*mut c_void>() };

                        let sym_desc = unsafe { entry.syms.add(sym).read() };
                        let val = if !sym_desc.section() == 0
                            && (sym_desc.other() & 3 != 0 || (sym_desc.info() >> 4) == 0)
                        {
                            // local or protected symbol. We know what the address is
                            base.wrapping_add(sym_desc.value() as usize)
                        } else {
                            let val = self.find_sym(name, true);

                            if val.is_null() && (sym_desc.info() >> 4) != 2 {
                                self.resolve_error(name, Error::SymbolNotFound)
                            }
                            val
                        };

                        debug_resolver!(
                            ResolverDebug::RELOCATIONS,
                            self,
                            "Resolving eager JUMP_SLOT relocation against {}: {val:p}",
                            unsafe { name.to_str_unchecked() }
                        );

                        let addend = rela.addend() as isize;

                        unsafe {
                            slot.write(val.offset(addend));
                        }
                    }
                    arch::JUMP_SLOT_RELOC => {
                        let sym = rela.symbol() as usize;
                        let name = get_sym_name(entry, sym);
                        debug_resolver!(
                            ResolverDebug::RELOCATIONS,
                            self,
                            "Resolving lazy JUMP_SLOT relocation against {}",
                            unsafe { name.to_str_unchecked() }
                        );
                        let offset = rela.at_offset() as usize;

                        let slot = unsafe { base.add(offset).cast::<*mut c_void>() };

                        let val = unsafe { base.wrapping_add(slot.read().addr()) };

                        debug_resolver!(
                            ResolverDebug::RELOCATIONS,
                            self,
                            "Resolving lazy JUMP_SLOT relocation against {}: {val:p}",
                            unsafe { name.to_str_unchecked() }
                        );
                        unsafe {
                            slot.write(val);
                        }
                    }
                    x => {
                        if let Some(mut loader) = self.head.loader {
                            use core::fmt::Write as _;
                            let _ = writeln!(loader, "{soname}: Unexpected relocation type {x}");
                        }
                    }
                }
            }
        }

        if let Some(init) = unsafe { core::mem::transmute::<_, Option<extern "C" fn()>>(init) } {
            init()
        }

        if let Some(init_arr) =
            unsafe { core::ptr::slice_from_raw_parts(init_array, init_arraysz).as_ref() }
        {
            for &init in init_arr {
                if init.is_null() || init.addr() == !0 {
                    continue;
                }
                if let Some(init) =
                    unsafe { core::mem::transmute::<_, Option<extern "C" fn()>>(init) }
                {
                    init()
                }
            }
        }

        entry
    }

    #[inline]
    pub fn is_loaded(&self, needed: &CStr) -> bool {
        use core::fmt::Write as _;
        debug_resolver!(
            ResolverDebug::LIB_SEARCH,
            self,
            "Checking is_loaded({})",
            unsafe { needed.to_str_unchecked() }
        );
        for ent in self.live_entries() {
            if let Some(name) = ent.name {
                let name = unsafe { cstr_from_ptr(name.as_ptr()) };

                debug_resolver!(ResolverDebug::LIB_SEARCH, self, "Found {}", unsafe {
                    name.to_str_unchecked()
                });
                if unsafe { cstr_from_ptr(name.as_ptr()) } == needed {
                    return true;
                }
            }
        }

        match self.head.delegate {
            Some(delegate) => delegate.is_loaded(needed),
            None => false,
        }
    }

    #[inline]
    pub fn find_sym_offset_in(&self, name: &CStr, ent: &DynEntry) -> usize {
        use core::fmt::Write;
        if let Some(gnu_hash) = unsafe { ent.gnu_hash.as_ref() } {
            debug_resolver!(
                ResolverDebug::HASH_LOOKUP,
                self,
                "Searching for symbol {} in GNU_HASH library {}",
                unsafe { name.to_str_unchecked() },
                ent.name
                    .as_deref()
                    .map(|v| unsafe { v.to_str_unchecked() })
                    .unwrap_or("<unnamed>")
            );
            let hash = hash::gnu_hash(name);

            let bloom_ent = (hash / usize::BITS) % (gnu_hash.bloom_size);
            let bloom_pos1 = hash % usize::BITS;
            let bloom_pos2 = (hash >> gnu_hash.bloom_shift) % usize::BITS;

            let bloom_base = unsafe { ent.gnu_hash.add(1).cast::<usize>() };
            let bucket_base = unsafe { bloom_base.add(gnu_hash.bloom_size as usize).cast::<u32>() };
            let chain_base = unsafe { bucket_base.add(gnu_hash.nbuckets as usize) };

            let bloom_ptr = unsafe { bloom_base.add(bloom_ent as usize).read() };

            if (bloom_ptr & (1 << bloom_pos1)) == 0 || (bloom_ptr & (1 << bloom_pos2)) == 0 {
                return !0;
            }
            let hash_ent = hash % gnu_hash.nbuckets;

            let bucket = unsafe { bucket_base.add(hash_ent as usize).read() };
            let Some(chain_ent) = bucket.checked_sub(gnu_hash.symoffset) else {
                return !0;
            };

            let chain_start = unsafe { chain_base.add(chain_ent as usize) };
            'inner: {
                for i in 0.. {
                    core::hint::black_box(i);
                    let chain = unsafe { chain_start.add(i).read() };

                    if (hash & !1) == (chain & !1) {
                        let sym = bucket as usize + i;
                        let e_name = get_sym_name(ent, sym);

                        if e_name == name {
                            break 'inner sym;
                        } else {
                            continue;
                        }
                    }

                    if (chain & 1) == 1 {
                        break 'inner !0;
                    }
                }

                break 'inner !0;
            }
        } else {
            debug_resolver!(
                ResolverDebug::HASH_LOOKUP,
                self,
                "Searching for symbol {} in SYSV_HASH library {}",
                unsafe { name.to_str_unchecked() },
                ent.name
                    .as_deref()
                    .map(|v| unsafe { v.to_str_unchecked() })
                    .unwrap_or("<unnamed>")
            );
            let nbuckets = unsafe { ent.hash.read() };
            let nchain = unsafe { ent.hash.add(1).read() };
            let buckets = unsafe { ent.hash.add(2) };
            let chain = unsafe { buckets.add(nbuckets as usize) };

            let hash = hash::svr4_hash(name) % nbuckets;

            let mut bucket = unsafe { buckets.add(hash as usize).read() };

            loop {
                let e_name = get_sym_name(ent, bucket as usize);
                let sym = unsafe { ent.syms.add(bucket as usize).read() };
                let _ = writeln!(
                    { self },
                    "Checking symbol in bucket {bucket} has name {}",
                    unsafe { core::str::from_utf8_unchecked(e_name.to_bytes()) }
                );

                if e_name == name {
                    if sym.section() == 0 {
                        return !0;
                    }
                    break;
                }

                bucket = unsafe { chain.add(bucket as usize).read() };
                if bucket == 0 {
                    return !0;
                }
            }

            bucket as usize
        }
    }

    #[inline]
    pub fn find_sym_in(&self, name: &CStr, ent: &DynEntry, process_ifunc: bool) -> *mut c_void {
        use core::fmt::Write as _;
        let sym = self.find_sym_offset_in(name, ent);

        if sym == !0 {
            core::ptr::null_mut()
        } else {
            let sym = unsafe { &*ent.syms.add(sym) };

            let val = sym.value() as usize;

            if sym.binding() == STB_WEAK && sym.section() == 0 {
                return core::ptr::null_mut();
            }

            let addr = unsafe { ent.base.add(val) };

            if process_ifunc && (sym.sym_type() == STT_GNU_IFUNC) {
                let prototy: unsafe extern "C" fn() -> *mut c_void =
                    unsafe { core::mem::transmute(addr) };
                unsafe { prototy() }
            } else {
                addr
            }
        }
    }

    #[inline]
    pub fn find_sym_module_offset(&self, name: &CStr) -> Option<(&DynEntry, usize)> {
        for ent in self.live_entries() {
            let sym = self.find_sym_offset_in(name, ent);

            if sym != !0 {
                return Some((ent, sym));
            }
        }
        None
    }

    #[inline]
    pub fn find_sym(&self, name: &CStr, process_ifunc: bool) -> *mut c_void {
        let ents = self.live_entries();
        for ent in ents {
            let addr = self.find_sym_in(name, ent, process_ifunc);

            if !addr.is_null() {
                return addr;
            }
        }

        if let Some(delegate) = self.head.delegate {
            delegate.find_sym(name, process_ifunc)
        } else {
            core::ptr::null_mut()
        }
    }
}

impl core::fmt::Write for &Resolver {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        if let Some(loader) = self.head.loader {
            loader.write_str(s)
        } else {
            Ok(())
        }
    }
}

const _: () = assert!(core::mem::size_of::<Resolver>() == 8192);

#[inline(always)]
pub fn get_sym_name(ent: &DynEntry, n: usize) -> &CStr {
    let sym_tab = ent.syms;

    let sym = unsafe { sym_tab.add(n) };

    let idx = unsafe { (*sym).name_idx() } as usize;

    let str_tab = ent.strtab;

    let name = unsafe { str_tab.add(idx) };

    unsafe { cstr_from_ptr(name) }
}

#[cfg_attr(target_arch = "x86_64", path = "resolver/x86_64.rs")]
mod arch;

pub mod hash;
