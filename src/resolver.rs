use core::{
    cell::SyncUnsafeCell,
    ffi::{CStr, c_char, c_void},
    mem::offset_of,
    sync::atomic::{AtomicUsize, Ordering},
};

use bytemuck::Zeroable;

use crate::{
    elf::{
        DynEntryType, ElfClass, ElfDyn, ElfGnuHashHeader, ElfRela, ElfRelocation, ElfSym, ElfSymbol,
    },
    helpers::cstr_from_ptr,
    safe_addr_of,
};

#[cfg_attr(target_pointer_width = "64", repr(C, align(128)))]
#[cfg_attr(target_pointer_width = "32", repr(C, align(64)))]
#[derive(Copy, Clone, Zeroable)]
pub struct DynEntry {
    got: *mut *const c_void,
    base: *mut c_void,
    syms: *const ElfSym,
    name: Option<&'static &'static str>,
    strtab: *const c_char,
    hash: *const u32,
    plt_rela: *const ElfRela,
    resolver: Option<&'static Resolver>,
    gnu_hash: *const ElfGnuHashHeader,
}

unsafe impl Send for DynEntry {}
unsafe impl Sync for DynEntry {}

#[cfg_attr(target_pointer_width = "64", repr(C, align(128)))]
#[cfg_attr(target_pointer_width = "32", repr(C, align(64)))]
struct ResolverHead {
    entry_count: AtomicUsize,
    has_entered_resolve_fn: AtomicUsize,
    cb_resolve_err: Option<fn(&CStr) -> !>,
    cb_resolve_needed: Option<fn(&CStr, &Resolver, *mut c_void)>,
}

unsafe impl Zeroable for ResolverHead {}

const RESOLVER_ENTRY_COUNT: usize =
    (4096 - core::mem::size_of::<ResolverHead>()) / core::mem::size_of::<DynEntry>();

#[repr(C, align(4096))]
pub struct Resolver {
    head: ResolverHead,
    entries: SyncUnsafeCell<[DynEntry; RESOLVER_ENTRY_COUNT]>,
}

unsafe impl Zeroable for Resolver {}

pub struct ResolveError {}

impl Resolver {
    pub const ZERO: Self = bytemuck::zeroed();

    #[inline(always)]
    pub fn resolve_error(&self, sym: &CStr) -> ! {
        match self.head.cb_resolve_err {
            Some(cb_resolve_error)
                if self.head.has_entered_resolve_fn.swap(1, Ordering::Relaxed) == 0 =>
            {
                cb_resolve_error(sym)
            }
            _ => crate::arch::crash_unrecoverably(),
        }
    }

    #[inline(always)]
    pub fn set_resolve_error_callback(&mut self, cb_resolve_err: fn(&CStr) -> !) {
        self.head.cb_resolve_err = Some(cb_resolve_err);
    }

    #[inline(always)]
    pub fn set_resolve_needed(&mut self, cb_resolve_needed: fn(&CStr, &Resolver, *mut c_void)) {
        self.head.cb_resolve_needed = Some(cb_resolve_needed);
    }

    #[inline(always)]
    pub fn live_entries(&self) -> &[DynEntry] {
        let mut count = self.head.entry_count.load(Ordering::Acquire);
        count = (count & 0xFFFF) - (count >> 16);
        let entries = self.entries.get().as_mut_ptr();

        unsafe { core::slice::from_raw_parts(entries, count) }
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
        name: &'static &'static str,
        udata: *mut c_void,
    ) -> &'static DynEntry {
        let mut entry = DynEntry {
            got: core::ptr::null_mut(),
            base,
            syms: core::ptr::null(),
            name: Some(name),
            strtab: core::ptr::null(),
            hash: core::ptr::null(),
            plt_rela: core::ptr::null(),
            resolver: Some(self),
            gnu_hash: core::ptr::null(),
        };

        let mut rela = core::ptr::null::<ElfRela>();
        let mut rela_count = 0;

        let mut resolve_now = false;

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
                    resolve_now &= (ent.d_val & 0x8) != 0;
                }
                DynEntryType::DT_FLAGS_1 => {
                    resolve_now &= (ent.d_val & 1) != 0;
                }
                DynEntryType::DT_RELA => {
                    rela = base.wrapping_add(ent.d_val as usize).cast();
                }
                DynEntryType::DT_RELASZ => {
                    rela_count = ent.d_val as usize / core::mem::size_of::<ElfRela>();
                }
                _ => {}
            }
        }
        let i = self
            .head
            .entry_count
            .fetch_add(0x00010001, Ordering::Relaxed)
            & 0xFFFF;
        if i > RESOLVER_ENTRY_COUNT {
            panic!("Max Open Objects reached {i}");
        }
        let ptr = unsafe { self.entries.get().cast::<DynEntry>().add(i) };

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

        'a: for ent in dyn_ent {
            if ent.d_tag == DynEntryType::DT_NEEDED {
                let needed: &CStr = unsafe { cstr_from_ptr(entry.strtab.add(ent.d_val as usize)) };
                let st = needed.to_bytes();

                for ent in self.live_entries() {
                    if let Some(&name) = ent.name {
                        if name.as_bytes() == st {
                            continue 'a;
                        }
                    }
                }

                if let Some(cb) = self.head.cb_resolve_needed {
                    cb(needed, self, udata)
                } else {
                    self.resolve_error(needed)
                }
            }
        }

        if rela.is_null() {
            return entry;
        }
        let rela = unsafe { core::slice::from_raw_parts(rela, rela_count) };

        for rela in rela {
            match rela.rel_type() {
                arch::JUMP_SLOT_RELOC if !resolve_now => {}
                arch::GLOB_DAT_RELOC | arch::JUMP_SLOT_RELOC => {
                    let sym = rela.symbol() as usize;

                    let name = get_sym_name(entry, sym);

                    let val = self.find_sym(name);

                    if val.is_null() {
                        self.resolve_error(name)
                    }

                    let addend = rela.addend() as isize;

                    let offset = rela.at_offset() as usize;

                    let slot = unsafe { base.add(offset).cast::<*mut c_void>() };
                    unsafe {
                        slot.write(val.offset(addend));
                    }
                }
                _ => todo!(),
            }
        }
        entry
    }

    #[inline(always)]
    pub fn find_sym(&self, name: &CStr) -> *mut c_void {
        'entloop: for ent in self.live_entries() {
            let sym = if let Some(gnu_hash) = unsafe { ent.gnu_hash.as_ref() } {
                let hash = hash::gnu_hash(name);

                let bloom_ent = (hash / usize::BITS) % (gnu_hash.bloom_size);
                let bloom_pos1 = hash % usize::BITS;
                let bloom_pos2 = (hash >> gnu_hash.bloom_shift) % usize::BITS;

                let bloom_base = unsafe { ent.gnu_hash.add(1).cast::<usize>() };
                let bucket_base =
                    unsafe { bloom_base.add(gnu_hash.bloom_size as usize).cast::<u32>() };
                let chain_base = unsafe { bucket_base.add(gnu_hash.nbuckets as usize) };

                let bloom_ptr = unsafe { bloom_base.add(bloom_ent as usize).read() };

                if (bloom_ptr & (1 << bloom_pos1)) == 0 || (bloom_ptr & (1 << bloom_pos2)) == 0 {
                    continue 'entloop;
                }
                let hash_ent = hash % gnu_hash.nbuckets;

                let bucket = unsafe { bucket_base.add(hash_ent as usize).read() };
                let chain_ent = bucket - gnu_hash.symoffset;

                let chain_start = unsafe { chain_base.add(chain_ent as usize) };
                'inner: {
                    for i in 0.. {
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
            };

            if sym == 0 {
                continue;
            } else {
                let sym = unsafe { ent.syms.add(sym) };
                let val = unsafe { (*sym).value() as usize };

                return unsafe { ent.base.add(val) };
            }
        }

        core::ptr::null_mut()
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

mod hash;
