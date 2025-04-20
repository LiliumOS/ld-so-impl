use core::{
    cell::SyncUnsafeCell,
    ffi::{CStr, c_char, c_void},
    mem::offset_of,
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering},
};

use bytemuck::Zeroable;

use crate::{
    arch::crash_unrecoverably,
    elf::{
        DynEntryType, ElfClass, ElfDyn, ElfGnuHashHeader, ElfHeader, ElfPhdr, ElfRela,
        ElfRelocation, ElfSym, ElfSymbol,
        consts::{PF_R, PF_W, PF_X, PT_DYNAMIC, PT_GNU_STACK, PT_LOAD, PT_TLS, ProgramType},
    },
    helpers::{NamePtr, cstr_from_ptr, strlen_impl},
    loader::{Error, LoaderImpl},
    safe_addr_of,
};

#[cfg_attr(target_pointer_width = "64", repr(C, align(128)))]
#[cfg_attr(target_pointer_width = "32", repr(C, align(64)))]
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

    #[cfg(feature = "tls")]
    tls_module: usize,
}

unsafe impl Send for DynEntry {}
unsafe impl Sync for DynEntry {}

#[cfg_attr(target_pointer_width = "64", repr(C, align(128)))]
#[cfg_attr(target_pointer_width = "32", repr(C, align(64)))]
struct ResolverHead {
    entry_count: AtomicUsize,
    has_entered_resolve_fn: AtomicUsize,
    cb_resolve_err: Option<fn(&CStr, Error) -> !>,
    loader: Option<&'static (dyn LoaderImpl + Sync)>,
    delegate: Option<&'static Resolver>,
    force_resolve_now: bool,
}

const STATIC_RESOLVER_ENTRY_COUNT: usize =
    (4096 - core::mem::size_of::<ResolverHead>()) / core::mem::size_of::<DynEntry>();

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

pub struct ResolveError {}

impl Resolver {
    pub const ZERO: Self = Self {
        head: ResolverHead {
            entry_count: AtomicUsize::new(0),
            has_entered_resolve_fn: AtomicUsize::new(0),
            cb_resolve_err: None,
            loader: None,
            delegate: None,
            force_resolve_now: false,
        },
        static_entries: SyncUnsafeCell::new(bytemuck::zeroed()),
    };

    pub fn force_resolve_now(&mut self) {
        self.head.force_resolve_now = true;
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
    pub fn live_entries(&self) -> &[DynEntry] {
        let mut count = self.head.entry_count.load(Ordering::Acquire);
        let entries = self.static_entries.get().as_mut_ptr();

        unsafe { core::slice::from_raw_parts(entries, count) }
    }

    pub unsafe fn load_from_handle(
        &'static self,
        soname: Option<&'static CStr>,
        udata: *mut c_void,
        fhdl: *mut c_void,
    ) -> &'static DynEntry {
        let Some(loader) = self.head.loader else {
            self.resolve_error(soname.unwrap_or(c"<unnamed module>"), Error::Fatal)
        };
        match unsafe { self.load_impl(soname, udata, loader, fhdl) } {
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
                    && ((phdr.p_type == PT_LOAD)/*|| (phdr.p_type == PT_GNU_STACK)*/)
            }) {
                return Err(Error::WritableText);
            }
        }

        let addr = unsafe { loader.alloc_base_addr(udata, highest_pma)? };

        let addr = unsafe { loader.map_phdrs(load_segments, fd, addr)? };

        let mut tls_module = !0;

        if cfg!(feature = "tls") {
            if let Some(phdr) = phdrs.iter().find(|v| v.p_type == PT_TLS) {
                tls_module = loader.alloc_tls(phdr.p_memsz as usize, phdr.p_align as usize)?;

                loader.load_tls(tls_module, fd, phdr.p_offset, phdr.p_filesz)?;
            }
        }

        let dyn_addr = addr
            .wrapping_add(dyn_phdr.p_paddr as usize)
            .cast::<ElfDyn>()
            .cast_const();

        let mut end = dyn_addr;

        while unsafe { (*end).d_tag } != DynEntryType::DT_NULL {
            unsafe { end = end.add(1) }
        }

        let dyn_seg = unsafe { core::slice::from_ptr_range(dyn_addr..end) };

        Ok(unsafe { self.resolve_object(addr, dyn_seg, soname, udata, tls_module) })
    }

    pub unsafe fn load(
        &'static self,
        name: &'static CStr,
        udata: *mut c_void,
    ) -> &'static DynEntry {
        let Some(loader) = self.head.loader else {
            self.resolve_error(name, Error::Fatal)
        };

        match unsafe { loader.find(name, udata) }
            .and_then(|fhdl| unsafe { self.load_impl(Some(name), udata, loader, fhdl) })
        {
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
        #[allow(unused_variables)] tls_module: usize,
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
            #[cfg(feature = "tls")]
            tls_module,
        };

        let mut rela = core::ptr::null::<ElfRela>();
        let mut rela_count = 0;

        let mut resolve_now = self.head.force_resolve_now;

        let mut init = core::ptr::null::<c_void>();
        let mut init_array = core::ptr::null::<*const c_void>();
        let mut init_arraysz = 0;

        for ent in dyn_ent {
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
                DynEntryType::DT_SONAME => {
                    if entry.name.is_none() {
                        let _ = entry.name.insert(unsafe {
                            NamePtr::new_unchecked(NonNull::new_unchecked(
                                base.wrapping_add(ent.d_val as usize).cast(),
                            ))
                        });
                    }
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
                _ => {}
            }
        }
        let i = self
            .head
            .entry_count
            .fetch_add(0x00010001, Ordering::Relaxed)
            & 0xFFFF;
        if i > STATIC_RESOLVER_ENTRY_COUNT {
            panic!("Max Open Objects reached {i}");
        }
        let ptr = unsafe { self.static_entries.get().cast::<DynEntry>().add(i) };

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

        self.head
            .entry_count
            .fetch_sub(0x00010000, Ordering::Release);

        for ent in dyn_ent {
            if ent.d_tag == DynEntryType::DT_NEEDED {
                let needed: &CStr = unsafe { cstr_from_ptr(entry.strtab.add(ent.d_val as usize)) };

                if self.is_loaded(needed) {
                    continue;
                }

                unsafe {
                    self.load(needed, udata);
                }
            }
        }

        if rela.is_null() {
            return entry;
        }
        let rela = unsafe { core::slice::from_raw_parts(rela, rela_count) };

        let soname = if let Some(soname) = entry.name {
            unsafe {
                core::str::from_raw_parts(soname.as_ptr().cast(), strlen_impl(soname.as_ptr()))
            }
        } else {
            "<unnamed>"
        };

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

                        let val = self.find_sym(name);

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

                    let val = moff + off;

                    let offset = rela.at_offset() as usize;

                    let slot = unsafe { base.add(offset).cast::<usize>() };
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

                    let slot = unsafe { base.add(offset).cast::<usize>() };
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

        if resolve_now {
            let jumprel = unsafe { core::slice::from_raw_parts(entry.plt_rela, entry.plt_relasz) };

            for rela in jumprel {
                match rela.rel_type() {
                    arch::JUMP_SLOT_RELOC => {
                        let sym = rela.symbol() as usize;

                        let sym_desc = unsafe { entry.syms.add(sym).read() };
                        let val = if sym_desc.section() != 0
                            && (sym_desc.other() & 3 != 0 || (sym_desc.info() >> 4) == 0)
                        {
                            // local or protected symbol. We know what the address is
                            base.wrapping_add(sym_desc.value() as usize)
                        } else {
                            let name = get_sym_name(entry, sym);

                            let val = self.find_sym(name);

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
        for ent in self.live_entries() {
            if let Some(name) = ent.name {
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
        if let Some(gnu_hash) = unsafe { ent.gnu_hash.as_ref() } {
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
                        break 'inner 0;
                    }
                }

                break 'inner 0;
            }
        } else {
            let nbuckets = unsafe { ent.hash.read() };
            let nchain = unsafe { ent.hash.add(1).read() };
            let buckets = unsafe { ent.hash.add(2) };
            let chain = unsafe { buckets.add(nbuckets as usize) };

            let hash = hash::svr4_hash(name) % nbuckets;

            let mut bucket = unsafe { buckets.add(hash as usize).read() };

            while bucket != 0 {
                let e_name = get_sym_name(ent, bucket as usize);

                if e_name == name {
                    break;
                }

                bucket = unsafe { chain.add(bucket as usize).read() };
            }

            bucket as usize
        }
    }

    #[inline]
    pub fn find_sym_in(&self, name: &CStr, ent: &DynEntry) -> *mut c_void {
        use core::fmt::Write as _;
        let sym = self.find_sym_offset_in(name, ent);

        if sym == !0 {
            core::ptr::null_mut()
        } else {
            let sym = unsafe { ent.syms.add(sym) };
            let val = unsafe { (*sym).value() as usize };

            unsafe { ent.base.add(val) }
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
    pub fn find_sym(&self, name: &CStr) -> *mut c_void {
        let ents = self.live_entries();
        for ent in ents {
            let addr = self.find_sym_in(name, ent);

            if !addr.is_null() {
                return addr;
            }
        }

        if let Some(delegate) = self.head.delegate {
            delegate.find_sym(name)
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

const _: () = assert!(core::mem::size_of::<Resolver>() == 4096);

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
