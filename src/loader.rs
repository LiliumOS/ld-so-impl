use core::ffi::{CStr, c_void};

use crate::{
    elf::{ElfAddr, ElfOffset, ElfPhdr},
    resolver::Resolver,
};

#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    AssumePresent,
    SymbolNotFound,
    ObjectNotFound,
    MalformedObject,
    ReadError,
    LoadError,
    AllocError,
    Fatal,
}

pub trait LoaderImpl {
    unsafe fn alloc_base_addr(
        &self,
        udata: *mut c_void,
        max_pma: ElfAddr,
    ) -> Result<*mut c_void, Error>;
    unsafe fn find(&self, soname: &CStr, udata: *mut c_void) -> Result<*mut c_void, Error>;
    unsafe fn map_phdrs(
        &self,
        phdrs: &[ElfPhdr],
        map_desc: *mut c_void,
        base_addr: *mut c_void,
    ) -> Result<*mut c_void, Error>;
    fn read_offset(
        &self,
        off: ElfOffset,
        map_desc: *mut c_void,
        sl: &mut [u8],
    ) -> Result<(), Error>;
}

impl<P: core::ops::Deref> LoaderImpl for P
where
    P::Target: LoaderImpl,
{
    unsafe fn alloc_base_addr(
        &self,
        udata: *mut c_void,
        max_pma: ElfAddr,
    ) -> Result<*mut c_void, Error> {
        unsafe { <P::Target as LoaderImpl>::alloc_base_addr(&self, udata, max_pma) }
    }

    unsafe fn find(&self, soname: &CStr, udata: *mut c_void) -> Result<*mut c_void, Error> {
        unsafe { <P::Target as LoaderImpl>::find(&self, soname, udata) }
    }

    unsafe fn map_phdrs(
        &self,
        phdrs: &[ElfPhdr],
        map_desc: *mut c_void,
        base_addr: *mut c_void,
    ) -> Result<*mut c_void, Error> {
        unsafe { <P::Target as LoaderImpl>::map_phdrs(&self, phdrs, map_desc, base_addr) }
    }

    fn read_offset(
        &self,
        off: ElfOffset,
        map_desc: *mut c_void,
        sl: &mut [u8],
    ) -> Result<(), Error> {
        <P::Target as LoaderImpl>::read_offset(self, off, map_desc, sl)
    }
}
