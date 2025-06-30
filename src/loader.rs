use core::ffi::{CStr, c_void};

#[cfg(feature = "debug")]
use crate::lddebug::LinkMap;
use crate::{
    elf::{ElfAddr, ElfOffset, ElfPhdr, ElfSize},
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
    WritableText,
    NoMemory,
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

    fn allocate_next(&self) -> Result<*mut Resolver, Error> {
        Err(Error::NoMemory)
    }

    #[allow(unused_variables)]
    fn write_str(&self, st: &str) -> core::fmt::Result {
        Ok(())
    }

    #[allow(unused_variables)]
    unsafe fn close_hdl(&self, hdl: *mut c_void) {}

    #[cfg(feature = "tls")]
    #[allow(unused_variables)]
    fn alloc_tls(&self, tls_size: usize, tls_align: usize, exec_tls: bool) -> Result<isize, Error> {
        Err(Error::AllocError)
    }

    #[cfg(feature = "tls")]
    #[allow(unused_variables)]
    unsafe fn load_tls(
        &self,
        tls_module: isize,
        laddr: *mut c_void,
        sz: ElfSize,
    ) -> Result<(), Error> {
        Err(Error::LoadError)
    }

    #[cfg(feature = "tls")]
    #[allow(unused_variables)]
    fn tls_direct_offset(&self, module: isize) -> Result<isize, Error> {
        Err(Error::LoadError)
    }

    #[cfg(feature = "debug")]
    fn alloc_link_node(&self) -> *mut LinkMap {
        core::ptr::null_mut()
    }
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

    fn allocate_next(&self) -> Result<*mut Resolver, Error> {
        <P::Target as LoaderImpl>::allocate_next(self)
    }

    fn write_str(&self, st: &str) -> core::fmt::Result {
        <P::Target as LoaderImpl>::write_str(self, st)
    }

    unsafe fn close_hdl(&self, hdl: *mut c_void) {
        unsafe { <P::Target as LoaderImpl>::close_hdl(self, hdl) }
    }

    #[cfg(feature = "tls")]
    fn alloc_tls(&self, tls_size: usize, tls_align: usize, exec_tls: bool) -> Result<isize, Error> {
        <P::Target as LoaderImpl>::alloc_tls(self, tls_size, tls_align, exec_tls)
    }

    #[cfg(feature = "tls")]
    unsafe fn load_tls(
        &self,
        tls_module: isize,
        laddr: *mut c_void,
        sz: ElfSize,
    ) -> Result<(), Error> {
        unsafe { <P::Target as LoaderImpl>::load_tls(self, tls_module, laddr, sz) }
    }

    #[cfg(feature = "tls")]
    fn tls_direct_offset(&self, module: isize) -> Result<isize, Error> {
        <P::Target as LoaderImpl>::tls_direct_offset(self, module)
    }

    #[cfg(feature = "debug")]
    fn alloc_link_node(&self) -> *mut LinkMap {
        <P::Target as LoaderImpl>::alloc_link_node(self)
    }
}

impl core::fmt::Write for &(dyn LoaderImpl + '_) {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        <dyn LoaderImpl as LoaderImpl>::write_str(*self, s)
    }
}

impl core::fmt::Write for &(dyn LoaderImpl + Sync + '_) {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        <dyn LoaderImpl as LoaderImpl>::write_str(*self, s)
    }
}
