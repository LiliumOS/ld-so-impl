use core::{fmt::Debug, hash::Hash};

use bytemuck::{Pod, Zeroable};

use crate::{
    debug::PrintHex,
    traits::{Numeric, private::Sealed},
};

#[cfg(target_pointer_width = "64")]
pub type ElfHost = Elf64;
#[cfg(target_pointer_width = "32")]
pub type ElfHost = Elf32;

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum PltType {
    Lazy,
    NonLazy,
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct PltEntryReloc<H> {
    pub offset: usize,
    pub howto: H,
    pub addend: usize,
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct PltEntryDesc<'a, H> {
    pub bytes: &'a [u8],
    /// The target of the relocation for the jump slot
    pub rel_dynent: Option<PltEntryReloc<H>>,
    /// The target of the relocation for the initial PLT Entry
    pub rel_plt_init: Option<PltEntryReloc<H>>,
    /// The target of the relocation for the Global Offset Table (The entire GOT/_GLOBAL_OFFSET_TABLE_ symbol)
    pub rel_got: Option<PltEntryReloc<H>>,
    /// The target of the relocation for the GOT Entry for the current symbol
    pub rel_got_entry: Option<PltEntryReloc<H>>,
    #[doc(hidden)]
    pub __non_exhaustive: (),
}

impl<'a, H> PltEntryDesc<'a, H> {
    pub const fn new() -> Self {
        Self {
            bytes: &[],
            rel_dynent: None,
            rel_got: None,
            rel_plt_init: None,
            rel_got_entry: None,
            __non_exhaustive: (),
        }
    }
}

impl<'a, H> Default for PltEntryDesc<'a, H> {
    fn default() -> Self {
        Self::new()
    }
}

pub type ElfByte<E = ElfHost> = <E as ElfClass>::Byte;
pub type ElfHalf<E = ElfHost> = <E as ElfClass>::Half;
pub type ElfWord<E = ElfHost> = <E as ElfClass>::Word;
pub type ElfSword<E = ElfHost> = <E as ElfClass>::Sword;
pub type ElfXword<E = ElfHost> = <E as ElfClass>::Xword;
pub type ElfSxword<E = ElfHost> = <E as ElfClass>::Sxword;
pub type ElfAddr<E = ElfHost> = <E as ElfClass>::Addr;
pub type ElfOffset<E = ElfHost> = <E as ElfClass>::Offset;
pub type ElfSection<E = ElfHost> = <E as ElfClass>::Section;
pub type ElfPhdr<E = ElfHost> = <E as ElfClass>::ProgramHeader;
pub type ElfVersym<E = ElfHost> = <E as ElfClass>::Versym;
pub type Symbol<E = ElfHost> = <E as ElfClass>::Symbol;
pub type ElfSize<E = ElfHost> = <E as ElfClass>::Size;

pub trait ElfSymbol: Sealed {
    type Class: ElfClass;
    fn name_idx(&self) -> ElfWord<Self::Class>;
    fn value(&self) -> ElfAddr<Self::Class>;
    fn size(&self) -> ElfSize<Self::Class>;
    fn info(&self) -> ElfByte<Self::Class>;
    fn other(&self) -> ElfByte<Self::Class>;
    fn section(&self) -> ElfSection<Self::Class>;
    fn sym_type(&self) -> consts::ElfSymbolType {
        bytemuck::must_cast(self.info().as_usize() as u8 & 0xF)
    }
    fn binding(&self) -> consts::ElfSymbolBinding {
        bytemuck::must_cast(self.info().as_usize() as u8 >> 4)
    }
    fn visibility(&self) -> consts::ElfSymbolVisibility {
        bytemuck::must_cast(self.other().as_usize() as u8 & 0x3)
    }
}

pub trait ElfRelocation: Sealed {
    type Class: ElfClass;
    fn at_offset(&self) -> ElfAddr<Self::Class>;
    fn rel_type(&self) -> ElfSize<Self::Class>;
    fn symbol(&self) -> ElfSize<Self::Class>;
    fn addend(&self) -> ElfOffset<Self::Class> {
        Numeric::zero()
    }
}

pub trait ElfProgramHeader: Sealed {
    type Class: ElfClass;
    fn pt_type(&self) -> consts::ProgramType;
    fn offset(&self) -> ElfOffset<Self::Class>;
    fn vaddr(&self) -> ElfAddr<Self::Class>;
    fn paddr(&self) -> ElfAddr<Self::Class>;
    fn memsize(&self) -> ElfSize<Self::Class>;
    fn filesize(&self) -> ElfSize<Self::Class>;
    fn align(&self) -> ElfSize<Self::Class>;
    fn flags(&self) -> ElfWord<Self::Class>;
}

pub trait ElfClass: Sealed + Sized + Copy + core::fmt::Debug + 'static {
    type Byte: Numeric;
    const EI_CLASS: consts::EiClass;
    type Half: Numeric;
    type Word: Numeric;
    type Sword: Numeric;
    type Xword: Numeric;
    type Sxword: Numeric;
    type Addr: Numeric;
    type Offset: Numeric;
    type Section: Numeric;
    type Versym: Numeric;
    type Size: Numeric;
    type Symbol: ElfSymbol<Class = Self> + Pod;
    type Rel: ElfRelocation<Class = Self> + Pod;
    type Rela: ElfRelocation<Class = Self> + Pod;
    type ProgramHeader: ElfProgramHeader<Class = Self> + Pod;
    type DynEntryType: Pod + Hash + Eq + Debug;

    fn new_sym(
        st_name: Self::Word,
        st_value: Self::Addr,
        st_size: Self::Size,
        st_info: u8,
        st_other: u8,
        st_shndx: Self::Half,
    ) -> Self::Symbol;

    fn mk_rinfo(symno: usize, relcode: usize) -> Self::Size;
}

#[derive(Copy, Clone, Debug)]
pub enum Elf64 {}

#[derive(Copy, Clone, Debug)]
pub enum Elf32 {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Zeroable, Pod)]
pub struct Elf32Sym {
    st_name: ElfWord<Elf32>,
    st_value: ElfAddr<Elf32>,
    st_size: ElfSize<Elf32>,
    st_info: ElfByte<Elf32>,
    st_other: ElfByte<Elf32>,
    st_shndx: ElfSection<Elf32>,
}

impl Sealed for Elf32Sym {}
impl ElfSymbol for Elf32Sym {
    type Class = Elf32;

    fn name_idx(&self) -> u32 {
        self.st_name
    }

    fn value(&self) -> <Self::Class as ElfClass>::Addr {
        self.st_value
    }

    fn size(&self) -> ElfSize<Self::Class> {
        self.st_size
    }

    fn info(&self) -> u8 {
        self.st_info
    }

    fn other(&self) -> u8 {
        self.st_other
    }

    fn section(&self) -> u16 {
        self.st_shndx
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Zeroable, Pod)]
pub struct Elf64Sym {
    st_name: ElfWord<Elf64>,
    st_info: ElfByte<Elf64>,
    st_other: ElfByte<Elf64>,
    st_shndx: ElfSection<Elf64>,
    st_value: ElfAddr<Elf64>,
    st_size: ElfSize<Elf64>,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ElfRel<Class: ElfClass> {
    r_offset: ElfAddr<Class>,
    r_info: ElfSize<Class>,
}

unsafe impl<Class: ElfClass> Zeroable for ElfRel<Class> {}
unsafe impl<Class: ElfClass> Pod for ElfRel<Class> {}

mod private {
    use super::*;
    pub trait ElfRelocationExtractHelpers: ElfClass {
        fn symbol(info: ElfSize<Self>) -> ElfSize<Self>;
        fn rel_type(info: ElfSize<Self>) -> ElfSize<Self>;
    }
}

use private::*;

pub use self::consts::ElfIdent;

impl<Class: ElfClass + ElfRelocationExtractHelpers> Sealed for ElfRel<Class> {}

impl<Class: ElfClass + ElfRelocationExtractHelpers> ElfRelocation for ElfRel<Class> {
    type Class = Class;

    fn at_offset(&self) -> <Self::Class as ElfClass>::Addr {
        self.r_offset
    }

    fn rel_type(&self) -> <Self::Class as ElfClass>::Size {
        Class::symbol(self.r_info)
    }

    fn symbol(&self) -> <Self::Class as ElfClass>::Size {
        Class::rel_type(self.r_info)
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ElfRela<Class: ElfClass = ElfHost> {
    r_offset: ElfAddr<Class>,
    r_info: ElfSize<Class>,
    r_addend: ElfOffset<Class>,
}

unsafe impl<Class: ElfClass> Zeroable for ElfRela<Class> {}
unsafe impl<Class: ElfClass> Pod for ElfRela<Class> {}

impl<Class: ElfClass + ElfRelocationExtractHelpers> Sealed for ElfRela<Class> {}

impl<Class: ElfClass + ElfRelocationExtractHelpers> ElfRelocation for ElfRela<Class> {
    type Class = Class;

    fn at_offset(&self) -> <Self::Class as ElfClass>::Addr {
        self.r_offset
    }

    fn rel_type(&self) -> <Self::Class as ElfClass>::Size {
        Class::rel_type(self.r_info)
    }

    fn symbol(&self) -> <Self::Class as ElfClass>::Size {
        Class::symbol(self.r_info)
    }
    fn addend(&self) -> <Self::Class as ElfClass>::Offset {
        self.r_addend
    }
}

impl Sealed for Elf64Sym {}
impl ElfSymbol for Elf64Sym {
    type Class = Elf64;

    fn name_idx(&self) -> u32 {
        self.st_name
    }

    fn value(&self) -> <Self::Class as ElfClass>::Addr {
        self.st_value
    }

    fn size(&self) -> ElfSize<Self::Class> {
        self.st_size
    }

    fn info(&self) -> u8 {
        self.st_info
    }

    fn other(&self) -> u8 {
        self.st_other
    }

    fn section(&self) -> u16 {
        self.st_shndx
    }
}

impl Sealed for Elf64 {}
impl ElfClass for Elf64 {
    const EI_CLASS: consts::EiClass = consts::ELFCLASS64;
    type Addr = u64;
    type Offset = i64;
    type Size = u64;
    type Symbol = Elf64Sym;
    type Rel = ElfRel<Self>;
    type Rela = ElfRela<Self>;

    type Byte = u8;

    type Half = u16;

    type Word = u32;

    type Sword = i32;

    type Xword = u64;

    type Sxword = u64;

    type Section = u16;

    type Versym = u16;

    type ProgramHeader = Elf64Phdr;

    type DynEntryType = consts::DynEntryType64;

    fn new_sym(
        st_name: Self::Word,
        st_value: Self::Addr,
        st_size: Self::Size,
        st_info: u8,
        st_other: u8,
        st_shndx: Self::Half,
    ) -> Self::Symbol {
        Elf64Sym {
            st_name,
            st_info,
            st_other,
            st_shndx,
            st_value,
            st_size,
        }
    }

    fn mk_rinfo(symno: usize, relcode: usize) -> Self::Size {
        ((symno as u64) << 32) + (relcode as u64)
    }
}

impl ElfRelocationExtractHelpers for Elf64 {
    fn symbol(info: Self::Size) -> Self::Size {
        info >> 32
    }

    fn rel_type(info: Self::Size) -> Self::Size {
        info & 0xffffffff
    }
}

impl Sealed for Elf32 {}
impl ElfClass for Elf32 {
    const EI_CLASS: consts::EiClass = consts::ELFCLASS32;
    type Addr = u32;
    type Offset = i32;
    type Size = u32;
    type Symbol = Elf32Sym;
    type Rel = ElfRel<Self>;
    type Rela = ElfRela<Self>;
    type Byte = u8;

    type Half = u16;

    type Word = u32;

    type Sword = i32;

    type Xword = u64;

    type Sxword = u64;

    type Section = u16;

    type Versym = u16;
    type ProgramHeader = Elf32Phdr;

    type DynEntryType = consts::DynEntryType64;

    fn new_sym(
        st_name: Self::Word,
        st_value: Self::Addr,
        st_size: Self::Size,
        st_info: u8,
        st_other: u8,
        st_shndx: Self::Half,
    ) -> Self::Symbol {
        Elf32Sym {
            st_name,
            st_value,
            st_size,
            st_info,
            st_other,
            st_shndx,
        }
    }

    fn mk_rinfo(symno: usize, relcode: usize) -> Self::Size {
        ((symno as u32) << 8) + (relcode as u32)
    }
}

impl ElfRelocationExtractHelpers for Elf32 {
    fn symbol(info: Self::Size) -> Self::Size {
        info >> 8
    }

    fn rel_type(info: Self::Size) -> Self::Size {
        info & 0xff
    }
}

pub mod consts {
    use bytemuck::{Pod, Zeroable};

    pub const ELFMAG: [u8; 4] = *b"\x7fELF";

    fake_enum::fake_enum! {
        #[repr(pub u16)]
        #[derive(Zeroable,Pod)]
        pub enum ElfType{
            ET_NONE = 0,
            ET_REL = 1,
            ET_EXEC = 2,
            ET_DYN = 3,
            ET_CORE = 4
        }
    }

    fake_enum::fake_enum! {
        #[repr(u16)]
        #[derive(Zeroable,Pod)]
        pub enum ElfMachine{
            EM_NONE = 0,           // No machine
            EM_M32 = 1,            // AT&T WE 32100
            EM_SPARC = 2,          // SPARC
            EM_386 = 3,            // Intel 386
            EM_68K = 4,            // Motorola 68000
            EM_88K = 5,            // Motorola 88000
            EM_IAMCU = 6,          // Intel MCU
            EM_860 = 7,            // Intel 80860
            EM_MIPS = 8,           // MIPS R3000
            EM_S370 = 9,           // IBM System/370
            EM_MIPS_RS3_LE = 10,   // MIPS RS3000 Little-endian
            EM_PARISC = 15,        // Hewlett-Packard PA-RISC
            EM_VPP500 = 17,        // Fujitsu VPP500
            EM_SPARC32PLUS = 18,   // Enhanced instruction set SPARC
            EM_960 = 19,           // Intel 80960
            EM_PPC = 20,           // PowerPC
            EM_PPC64 = 21,         // PowerPC64
            EM_S390 = 22,          // IBM System/390
            EM_SPU = 23,           // IBM SPU/SPC
            EM_V800 = 36,          // NEC V800
            EM_FR20 = 37,          // Fujitsu FR20
            EM_RH32 = 38,          // TRW RH-32
            EM_RCE = 39,           // Motorola RCE
            EM_ARM = 40,           // ARM
            EM_ALPHA = 41,         // DEC Alpha
            EM_SH = 42,            // Hitachi SH
            EM_SPARCV9 = 43,       // SPARC V9
            EM_TRICORE = 44,       // Siemens TriCore
            EM_ARC = 45,           // Argonaut RISC Core
            EM_H8_300 = 46,        // Hitachi H8/300
            EM_H8_300H = 47,       // Hitachi H8/300H
            EM_H8S = 48,           // Hitachi H8S
            EM_H8_500 = 49,        // Hitachi H8/500
            EM_IA_64 = 50,         // Intel IA-64 processor architecture
            EM_MIPS_X = 51,        // Stanford MIPS-X
            EM_COLDFIRE = 52,      // Motorola ColdFire
            EM_68HC12 = 53,        // Motorola M68HC12
            EM_MMA = 54,           // Fujitsu MMA Multimedia Accelerator
            EM_PCP = 55,           // Siemens PCP
            EM_NCPU = 56,          // Sony nCPU embedded RISC processor
            EM_NDR1 = 57,          // Denso NDR1 microprocessor
            EM_STARCORE = 58,      // Motorola Star*Core processor
            EM_ME16 = 59,          // Toyota ME16 processor
            EM_ST100 = 60,         // STMicroelectronics ST100 processor
            EM_TINYJ = 61,         // Advanced Logic Corp. TinyJ embedded processor family
            EM_X86_64 = 62,        // AMD x86-64 architecture
            EM_PDSP = 63,          // Sony DSP Processor
            EM_PDP10 = 64,         // Digital Equipment Corp. PDP-10
            EM_PDP11 = 65,         // Digital Equipment Corp. PDP-11
            EM_FX66 = 66,          // Siemens FX66 microcontroller
            EM_ST9PLUS = 67,       // STMicroelectronics ST9+ 8/16 bit microcontroller
            EM_ST7 = 68,           // STMicroelectronics ST7 8-bit microcontroller
            EM_68HC16 = 69,        // Motorola MC68HC16 Microcontroller
            EM_68HC11 = 70,        // Motorola MC68HC11 Microcontroller
            EM_68HC08 = 71,        // Motorola MC68HC08 Microcontroller
            EM_68HC05 = 72,        // Motorola MC68HC05 Microcontroller
            EM_SVX = 73,           // Silicon Graphics SVx
            EM_ST19 = 74,          // STMicroelectronics ST19 8-bit microcontroller
            EM_VAX = 75,           // Digital VAX
            EM_CRIS = 76,          // Axis Communications 32-bit embedded processor
            EM_JAVELIN = 77,       // Infineon Technologies 32-bit embedded processor
            EM_FIREPATH = 78,      // Element 14 64-bit DSP Processor
            EM_ZSP = 79,           // LSI Logic 16-bit DSP Processor
            EM_MMIX = 80,          // Donald Knuth's educational 64-bit processor
            EM_HUANY = 81,         // Harvard University machine-independent object files
            EM_PRISM = 82,         // SiTera Prism
            EM_AVR = 83,           // Atmel AVR 8-bit microcontroller
            EM_FR30 = 84,          // Fujitsu FR30
            EM_D10V = 85,          // Mitsubishi D10V
            EM_D30V = 86,          // Mitsubishi D30V
            EM_V850 = 87,          // NEC v850
            EM_M32R = 88,          // Mitsubishi M32R
            EM_MN10300 = 89,       // Matsushita MN10300
            EM_MN10200 = 90,       // Matsushita MN10200
            EM_PJ = 91,            // picoJava
            EM_OPENRISC = 92,      // OpenRISC 32-bit embedded processor
            EM_ARC_COMPACT = 93,   // ARC International ARCompact processor (old
                                    // spelling/synonym: EM_ARC_A5)
            EM_XTENSA = 94,        // Tensilica Xtensa Architecture
            EM_VIDEOCORE = 95,     // Alphamosaic VideoCore processor
            EM_TMM_GPP = 96,       // Thompson Multimedia General Purpose Processor
            EM_NS32K = 97,         // National Semiconductor 32000 series
            EM_TPC = 98,           // Tenor Network TPC processor
            EM_SNP1K = 99,         // Trebia SNP 1000 processor
            EM_ST200 = 100,        // STMicroelectronics (www.st.com) ST200
            EM_IP2K = 101,         // Ubicom IP2xxx microcontroller family
            EM_MAX = 102,          // MAX Processor
            EM_CR = 103,           // National Semiconductor CompactRISC microprocessor
            EM_F2MC16 = 104,       // Fujitsu F2MC16
            EM_MSP430 = 105,       // Texas Instruments embedded microcontroller msp430
            EM_BLACKFIN = 106,     // Analog Devices Blackfin (DSP) processor
            EM_SE_C33 = 107,       // S1C33 Family of Seiko Epson processors
            EM_SEP = 108,          // Sharp embedded microprocessor
            EM_ARCA = 109,         // Arca RISC Microprocessor
            EM_UNICORE = 110,      // Microprocessor series from PKU-Unity Ltd. and MPRC
                                    // of Peking University
            EM_EXCESS = 111,       // eXcess: 16/32/64-bit configurable embedded CPU
            EM_DXP = 112,          // Icera Semiconductor Inc. Deep Execution Processor
            EM_ALTERA_NIOS2 = 113, // Altera Nios II soft-core processor
            EM_CRX = 114,          // National Semiconductor CompactRISC CRX
            EM_XGATE = 115,        // Motorola XGATE embedded processor
            EM_C166 = 116,         // Infineon C16x/XC16x processor
            EM_M16C = 117,         // Renesas M16C series microprocessors
            EM_DSPIC30F = 118,     // Microchip Technology dsPIC30F Digital Signal
                                    // Controller
            EM_CE = 119,           // Freescale Communication Engine RISC core
            EM_M32C = 120,         // Renesas M32C series microprocessors
            EM_TSK3000 = 131,      // Altium TSK3000 core
            EM_RS08 = 132,         // Freescale RS08 embedded processor
            EM_SHARC = 133,        // Analog Devices SHARC family of 32-bit DSP
                                    // processors
            EM_ECOG2 = 134,        // Cyan Technology eCOG2 microprocessor
            EM_SCORE7 = 135,       // Sunplus S+core7 RISC processor
            EM_DSP24 = 136,        // New Japan Radio (NJR) 24-bit DSP Processor
            EM_VIDEOCORE3 = 137,   // Broadcom VideoCore III processor
            EM_LATTICEMICO32 = 138, // RISC processor for Lattice FPGA architecture
            EM_SE_C17 = 139,        // Seiko Epson C17 family
            EM_TI_C6000 = 140,      // The Texas Instruments TMS320C6000 DSP family
            EM_TI_C2000 = 141,      // The Texas Instruments TMS320C2000 DSP family
            EM_TI_C5500 = 142,      // The Texas Instruments TMS320C55x DSP family
            EM_MMDSP_PLUS = 160,    // STMicroelectronics 64bit VLIW Data Signal Processor
            EM_CYPRESS_M8C = 161,   // Cypress M8C microprocessor
            EM_R32C = 162,          // Renesas R32C series microprocessors
            EM_TRIMEDIA = 163,      // NXP Semiconductors TriMedia architecture family
            EM_HEXAGON = 164,       // Qualcomm Hexagon processor
            EM_8051 = 165,          // Intel 8051 and variants
            EM_STXP7X = 166,        // STMicroelectronics STxP7x family of configurable
                                    // and extensible RISC processors
            EM_NDS32 = 167,         // Andes Technology compact code size embedded RISC
                                    // processor family
            EM_ECOG1 = 168,         // Cyan Technology eCOG1X family
            EM_ECOG1X = 168,        // Cyan Technology eCOG1X family
            EM_MAXQ30 = 169,        // Dallas Semiconductor MAXQ30 Core Micro-controllers
            EM_XIMO16 = 170,        // New Japan Radio (NJR) 16-bit DSP Processor
            EM_MANIK = 171,         // M2000 Reconfigurable RISC Microprocessor
            EM_CRAYNV2 = 172,       // Cray Inc. NV2 vector architecture
            EM_RX = 173,            // Renesas RX family
            EM_METAG = 174,         // Imagination Technologies META processor
                                    // architecture
            EM_MCST_ELBRUS = 175,   // MCST Elbrus general purpose hardware architecture
            EM_ECOG16 = 176,        // Cyan Technology eCOG16 family
            EM_CR16 = 177,          // National Semiconductor CompactRISC CR16 16-bit
                                    // microprocessor
            EM_ETPU = 178,          // Freescale Extended Time Processing Unit
            EM_SLE9X = 179,         // Infineon Technologies SLE9X core
            EM_L10M = 180,          // Intel L10M
            EM_K10M = 181,          // Intel K10M
            EM_AARCH64 = 183,       // ARM AArch64
            EM_AVR32 = 185,         // Atmel Corporation 32-bit microprocessor family
            EM_STM8 = 186,          // STMicroeletronics STM8 8-bit microcontroller
            EM_TILE64 = 187,        // Tilera TILE64 multicore architecture family
            EM_TILEPRO = 188,       // Tilera TILEPro multicore architecture family
            EM_CUDA = 190,          // NVIDIA CUDA architecture
            EM_TILEGX = 191,        // Tilera TILE-Gx multicore architecture family
            EM_CLOUDSHIELD = 192,   // CloudShield architecture family
            EM_COREA_1ST = 193,     // KIPO-KAIST Core-A 1st generation processor family
            EM_COREA_2ND = 194,     // KIPO-KAIST Core-A 2nd generation processor family
            EM_ARC_COMPACT2 = 195,  // Synopsys ARCompact V2
            EM_OPEN8 = 196,         // Open8 8-bit RISC soft processor core
            EM_RL78 = 197,          // Renesas RL78 family
            EM_VIDEOCORE5 = 198,    // Broadcom VideoCore V processor
            EM_78KOR = 199,         // Renesas 78KOR family
            EM_56800EX = 200,       // Freescale 56800EX Digital Signal Controller (DSC)
            EM_BA1 = 201,           // Beyond BA1 CPU architecture
            EM_BA2 = 202,           // Beyond BA2 CPU architecture
            EM_XCORE = 203,         // XMOS xCORE processor family
            EM_MCHP_PIC = 204,      // Microchip 8-bit PIC(r) family
            EM_INTEL205 = 205,      // Reserved by Intel
            EM_INTEL206 = 206,      // Reserved by Intel
            EM_INTEL207 = 207,      // Reserved by Intel
            EM_INTEL208 = 208,      // Reserved by Intel
            EM_INTEL209 = 209,      // Reserved by Intel
            EM_KM32 = 210,          // KM211 KM32 32-bit processor
            EM_KMX32 = 211,         // KM211 KMX32 32-bit processor
            EM_KMX16 = 212,         // KM211 KMX16 16-bit processor
            EM_KMX8 = 213,          // KM211 KMX8 8-bit processor
            EM_KVARC = 214,         // KM211 KVARC processor
            EM_CDP = 215,           // Paneve CDP architecture family
            EM_COGE = 216,          // Cognitive Smart Memory Processor
            EM_COOL = 217,          // iCelero CoolEngine
            EM_NORC = 218,          // Nanoradio Optimized RISC
            EM_CSR_KALIMBA = 219,   // CSR Kalimba architecture family
            EM_AMDGPU = 224,        // AMD GPU architecture
            EM_RISCV = 243,         // RISC-V
            EM_LANAI = 244,         // Lanai 32-bit processor
            EM_BPF = 247,           // Linux kernel bpf virtual machine
            EM_VE = 251,            // NEC SX-Aurora VE
            EM_CSKY = 252,          // C-SKY 32-bit processor
            EM_WC65C816 = 257,      // 65816/65c816

            EM_CLEVER     = 0x434C, // Clever-ISA
            EM_HOLEYBYTES = 0xAB1E, // Holey Bytes
        }
    }

    fake_enum::fake_enum! {
        #[repr(u8)]
        #[derive(Zeroable,Pod)]
        pub enum EiClass{
            ELFCLASSNONE = 0,
            ELFCLASS32 = 1,
            ELFCLASS64 = 2
        }
    }

    fake_enum::fake_enum! {
        #[repr(u8)]
        #[derive(Zeroable,Pod)]
        pub enum EiData{
            ELFDATANONE = 0,
            ELFDATA2LSB = 1,
            ELFDATA2MSB = 2
        }
    }

    fake_enum::fake_enum! {
        #[repr(u8)]
        #[derive(Zeroable,Pod)]
        pub enum EiVersion{
            EV_NONE = 0,
            EV_CURRENT = 1
        }
    }

    fake_enum::fake_enum! {
        #[repr(u8)]
        #[derive(Zeroable,Pod)]
        pub enum EiOsAbi{
            ELFOSABI_NONE = 0,           // UNIX System V ABI
            ELFOSABI_HPUX = 1,           // HP-UX operating system
            ELFOSABI_NETBSD = 2,         // NetBSD
            ELFOSABI_GNU = 3,            // GNU/Linux
            ELFOSABI_LINUX = 3,          // Historical alias for ELFOSABI_GNU.
            ELFOSABI_HURD = 4,           // GNU/Hurd
            ELFOSABI_SOLARIS = 6,        // Solaris
            ELFOSABI_AIX = 7,            // AIX
            ELFOSABI_IRIX = 8,           // IRIX
            ELFOSABI_FREEBSD = 9,        // FreeBSD
            ELFOSABI_TRU64 = 10,         // TRU64 UNIX
            ELFOSABI_MODESTO = 11,       // Novell Modesto
            ELFOSABI_OPENBSD = 12,       // OpenBSD
            ELFOSABI_OPENVMS = 13,       // OpenVMS
            ELFOSABI_NSK = 14,           // Hewlett-Packard Non-Stop Kernel
            ELFOSABI_AROS = 15,          // AROS
            ELFOSABI_FENIXOS = 16,       // FenixOS
            ELFOSABI_CLOUDABI = 17,      // Nuxi CloudABI
            ELFOSABI_FIRST_ARCH = 64,    // First architecture-specific OS ABI
            ELFOSABI_AMDGPU_HSA = 64,    // AMD HSA runtime
            ELFOSABI_AMDGPU_PAL = 65,    // AMD PAL runtime
            ELFOSABI_AMDGPU_MESA3D = 66, // AMD GCN GPUs (GFX6+) for MESA runtime
            ELFOSABI_ARM = 97,           // ARM
            ELFOSABI_C6000_ELFABI = 64,  // Bare-metal TMS320C6000
            ELFOSABI_C6000_LINUX = 65,   // Linux TMS320C6000
            ELFOSABI_STANDALONE = 255,   // Standalone (embedded) application
        }
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone, Debug, Zeroable, Pod)]
    pub struct ElfIdent {
        pub ei_mag: [u8; 4],
        pub ei_class: EiClass,
        pub ei_data: EiData,
        pub ei_version: EiVersion,
        pub ei_osabi: EiOsAbi,
        pub ei_abiversion: u8,
        pub ei_pad: [u8; 7],
    }

    const _: () = assert!(core::mem::size_of::<ElfIdent>() == 16);
    const _: () = assert!(core::mem::align_of::<ElfIdent>() == 1);

    fake_enum::fake_enum! {
        #[repr(pub u32)]
        #[derive(Zeroable,Pod)]
        pub enum ProgramType{
            PT_NULL = 0,
            PT_LOAD = 1,
            PT_DYNAMIC = 2,
            PT_INTERP = 3,
            PT_NOTE = 4,
            PT_SHLIB = 5,
            PT_PHDR = 6,
            PT_TLS = 7,

            PT_GNU_STACK = 0x6474e551,
        }
    }
    pub const PF_X: u32 = 1;
    pub const PF_W: u32 = 2;
    pub const PF_R: u32 = 4;

    fake_enum::fake_enum! {
        #[repr(pub u32)]
        #[derive(Zeroable,Pod)]
        pub enum SectionType{
            SHT_NULL = 0,
            SHT_PROGBITS = 1,
            SHT_SYMTAB = 2,
            SHT_STRTAB = 3,
            SHT_RELA = 4,
            SHT_HASH = 5,
            SHT_DYNAMIC = 6,
            SHT_NOTE = 7,
            SHT_NOBITS = 8,
            SHT_REL = 9,
            SHT_SHLIB = 10,
            SHT_DYNSYM = 11,
            SHT_GROUP = 17,
        }
    }

    fake_enum::fake_enum! {
        #[repr(pub u32)]
        #[derive(Zeroable,Pod, Hash)]
        pub enum struct DynEntryType32{
            DT_NULL = 0,
            DT_NEEDED = 1,
            DT_PLTRELSZ = 2,
            DT_PLTGOT = 3,
            DT_HASH = 4,
            DT_STRTAB = 5,
            DT_SYMTAB = 6,
            DT_RELA = 7,
            DT_RELASZ = 8,
            DT_RELAENT = 9,
            DT_STRSZ = 10,
            DT_SYMENT = 11,
            DT_INIT = 12,
            DT_FINI = 13,
            DT_SONAME = 14,
            DT_RPATH = 15,
            DT_SYMBOL = 16,
            DT_REL = 17,
            DT_RELSZ = 18,
            DT_RELENT = 19,
            DT_PLTREL = 20,
            DT_DEBUG = 21,
            DT_TEXTREL = 22,
            DT_JMPREL = 23,
            DT_BIND_NOW = 24,
            DT_INIT_ARRAY = 25,
            DT_FINI_ARRAY = 26,
            DT_INIT_ARRAYSZ = 27,
            DT_FINI_ARRAYSZ = 28,
            DT_RUNPATH = 29,
            DT_FLAGS = 30,
            DT_PREINIT_ARRAY = 32,
            DT_PREINIT_ARRAYSZ = 33,
            DT_LOOS = 0x6000000D,
            DT_HIOS = 0x6ffff000,
            DT_GNU_HASH = 0x6ffffef5,
            DT_FLAGS_1 = 0x6ffffffb,
            DT_LOPROC = 0x70000000,
            DT_HIPROC = 0x7fffffff,
        }
    }

    fake_enum::fake_enum! {
        #[repr(pub u64)]
        #[derive(Zeroable,Pod, Hash)]
        pub enum struct DynEntryType64{
            DT_NULL = 0,
            DT_NEEDED = 1,
            DT_PLTRELSZ = 2,
            DT_PLTGOT = 3,
            DT_HASH = 4,
            DT_STRTAB = 5,
            DT_SYMTAB = 6,
            DT_RELA = 7,
            DT_RELASZ = 8,
            DT_RELAENT = 9,
            DT_STRSZ = 10,
            DT_SYMENT = 11,
            DT_INIT = 12,
            DT_FINI = 13,
            DT_SONAME = 14,
            DT_RPATH = 15,
            DT_SYMBOL = 16,
            DT_REL = 17,
            DT_RELSZ = 18,
            DT_RELENT = 19,
            DT_PLTREL = 20,
            DT_DEBUG = 21,
            DT_TEXTREL = 22,
            DT_JMPREL = 23,
            DT_BIND_NOW = 24,
            DT_INIT_ARRAY = 25,
            DT_FINI_ARRAY = 26,
            DT_INIT_ARRAYSZ = 27,
            DT_FINI_ARRAYSZ = 28,
            DT_RUNPATH = 29,
            DT_FLAGS = 30,
            DT_PREINIT_ARRAY = 32,
            DT_PREINIT_ARRAYSZ = 33,
            DT_LOOS = 0x6000000D,
            DT_HIOS = 0x6ffff000,
            DT_GNU_HASH = 0x6ffffef5,
            DT_FLAGS_1 = 0x6ffffffb,
            DT_LOPROC = 0x70000000,
            DT_HIPROC = 0x7fffffff,
        }
    }

    fake_enum::fake_enum! {
        #[repr(u8)]
        #[derive(Zeroable,Pod)]
        pub enum ElfSymbolType {
            STT_NOTYPE = 0,
            STT_OBJECT = 1,
            STT_FUNC = 2,
            STT_SECTION = 3,
            STT_FILE = 4,
            STT_COMMON = 5,
            STT_TLS = 6,
            STT_GNU_IFUNC = 10,
        }
    }

    fake_enum::fake_enum! {
        #[repr(u8)]
        #[derive(Zeroable,Pod)]
        pub enum ElfSymbolBinding {
            STB_LOCAL = 0,
            STB_GLOBAL = 1,
            STB_WEAK = 2,
        }
    }

    fake_enum::fake_enum! {
        #[repr(u8)]
        #[derive(Zeroable, Pod)]
        pub enum ElfSymbolVisibility {
            STV_DEFAULT = 0,
            STV_INTERNAL = 1,
            STV_HIDDEN = 2,
            STV_PROTECTED = 3,
        }
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct ElfHeader<E: ElfClass = ElfHost> {
    pub e_ident: consts::ElfIdent,
    pub e_type: consts::ElfType,
    pub e_machine: consts::ElfMachine,
    pub e_version: ElfWord<E>,
    pub e_entry: ElfAddr<E>,
    pub e_phoff: ElfOffset<E>,
    pub e_shoff: ElfOffset<E>,
    pub e_flags: ElfWord<E>,
    pub e_ehsize: ElfHalf<E>,
    pub e_phentsize: ElfHalf<E>,
    pub e_phnum: ElfHalf<E>,
    pub e_shentsize: ElfHalf<E>,
    pub e_shnum: ElfHalf<E>,
    pub e_shstrndx: ElfHalf<E>,
}

unsafe impl<E: ElfClass> Zeroable for ElfHeader<E> {}
unsafe impl<E: ElfClass + 'static> Pod for ElfHeader<E> {}

pub trait SectionHeader {}

#[derive(Copy, Clone, Debug, Zeroable, Pod)]
#[repr(C)]
pub struct Elf32Phdr {
    pub p_type: consts::ProgramType,
    pub p_offset: ElfOffset<Elf32>,
    pub p_vaddr: ElfAddr<Elf32>,
    pub p_paddr: ElfAddr<Elf32>,
    pub p_filesz: ElfSize<Elf32>,
    pub p_memsz: ElfSize<Elf32>,
    pub p_flags: ElfWord<Elf32>,
    pub p_align: ElfSize<Elf32>,
}

impl Sealed for Elf32Phdr {}

impl ElfProgramHeader for Elf32Phdr {
    type Class = Elf32;

    fn pt_type(&self) -> consts::ProgramType {
        self.p_type
    }

    fn offset(&self) -> ElfOffset<Self::Class> {
        self.p_offset
    }

    fn vaddr(&self) -> ElfAddr<Self::Class> {
        self.p_vaddr
    }

    fn paddr(&self) -> ElfAddr<Self::Class> {
        self.p_paddr
    }

    fn memsize(&self) -> ElfSize<Self::Class> {
        self.p_memsz
    }

    fn filesize(&self) -> ElfSize<Self::Class> {
        self.p_filesz
    }

    fn align(&self) -> ElfSize<Self::Class> {
        self.p_align
    }

    fn flags(&self) -> ElfWord<Self::Class> {
        self.p_flags
    }
}

#[derive(Copy, Clone, Debug, Zeroable, Pod)]
#[repr(C)]
pub struct Elf64Phdr {
    pub p_type: consts::ProgramType,
    pub p_flags: ElfWord<Elf64>,
    pub p_offset: ElfOffset<Elf64>,
    pub p_vaddr: ElfAddr<Elf64>,
    pub p_paddr: ElfAddr<Elf64>,
    pub p_filesz: ElfSize<Elf64>,
    pub p_memsz: ElfSize<Elf64>,
    pub p_align: ElfSize<Elf64>,
}

impl Sealed for Elf64Phdr {}

impl ElfProgramHeader for Elf64Phdr {
    type Class = Elf64;

    fn pt_type(&self) -> consts::ProgramType {
        self.p_type
    }

    fn offset(&self) -> ElfOffset<Self::Class> {
        self.p_offset
    }

    fn vaddr(&self) -> ElfAddr<Self::Class> {
        self.p_vaddr
    }

    fn paddr(&self) -> ElfAddr<Self::Class> {
        self.p_paddr
    }

    fn memsize(&self) -> ElfSize<Self::Class> {
        self.p_memsz
    }

    fn filesize(&self) -> ElfSize<Self::Class> {
        self.p_filesz
    }

    fn align(&self) -> ElfSize<Self::Class> {
        self.p_align
    }

    fn flags(&self) -> ElfWord<Self::Class> {
        self.p_flags
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ElfSectionHeader<Class: ElfClass = ElfHost> {
    pub sh_name: ElfWord<Class>,
    pub sh_type: consts::SectionType,
    pub sh_flags: ElfOffset<Class>,
    pub sh_addr: ElfAddr<Class>,
    pub sh_offset: ElfOffset<Class>,
    pub sh_size: ElfSize<Class>,
    pub sh_link: ElfWord<Class>,
    pub sh_info: ElfWord<Class>,
    pub sh_addralign: ElfAddr<Class>,
    pub sh_entsize: ElfSize<Class>,
}

impl<Class: ElfClass> core::fmt::Debug for ElfSectionHeader<Class> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("ElfSectionHeader")
            .field("sh_name", &self.sh_name)
            .field("sh_type", &self.sh_type)
            .field("sh_flags", &PrintHex(self.sh_flags))
            .field("sh_addr", &PrintHex(self.sh_addr))
            .field("sh_offset", &self.sh_offset)
            .field("sh_size", &self.sh_size)
            .field("sh_link", &PrintHex(self.sh_link))
            .field("sh_info", &PrintHex(self.sh_info))
            .field("sh_addralign", &self.sh_addralign)
            .field("sh_entsize", &self.sh_entsize)
            .finish()
    }
}

unsafe impl<Class: ElfClass> Zeroable for ElfSectionHeader<Class> {}
unsafe impl<Class: ElfClass + 'static> Pod for ElfSectionHeader<Class> {}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct ElfDyn<Class: ElfClass = ElfHost> {
    pub d_tag: Class::DynEntryType,
    pub d_val: Class::Addr,
}

unsafe impl<Class: ElfClass + 'static> Pod for ElfDyn<Class> {}
unsafe impl<Class: ElfClass> Zeroable for ElfDyn<Class> {}

#[cfg(target_pointer_width = "32")]
pub use consts::DynEntryType32 as DynEntryType;
#[cfg(target_pointer_width = "64")]
pub use consts::DynEntryType64 as DynEntryType;

pub type ElfSym<Class = ElfHost> = <Class as ElfClass>::Symbol;

/// Used by the DT_GNU_HASH dynamic block
/// An optimized format for hashing, and horribly undocumented.
/// The algorithm used for this section is described by [`hash::gnu_hash`][crate::resolver::hash::gnu_hash].
///
/// ## `DT_GNU_HASH` Symbol Lookup
/// The lookup algorithm is roughly as follows: (Adapted partially from <https://flapenguin.me/elf-dt-gnu-hash>, but contains additional info, and may yet still be incomplete)
///
/// The structure of the whole [`DT_GNU_HASH`][DynEntryType::DT_GNU_HASH] tag is as follows:
/// ```rust,ignore
/// #[repr(C)]
/// pub struct ElfGnuHashTable {
///    pub head: ElfGnuHashHeader,
///    pub bloom: [usize; head.bloom_size], // `usize` is the appropriate `ElfX_Size` type - or the size type for the Elf Class
///    pub buckets: [u32; head.nbucket],
///    pub chain: [u32],
/// }
/// ```
///
/// To lookup a symbol with name `foo`, we compute the `hash` of `foo` using [`hash::gnu_hash(foo)`][crate::resolver::hash::gnu_hash].
/// We can then check this hash against the `bloom` filter as follows:
/// ```rust,ignore
/// let bloom_ent = (hash / usize::BITS) % head.bloom_size; // Again, this is actually `ElfX_Size` where `X` is the current ELFCLASS
/// let bloom_pos1 = hash % usize::BITS;
/// let bloom_pos2 = (hash >> head.bloom_shift) % usize::BITS; //
/// let bloom_val = head.bloom[bloom_ent as usize];
///
/// (bloom_val & (1 << bloom_pos1)) && (bloom_val & (1 << bloom_pos2))
/// ```
///
/// Note that testing both bits will not guarantee that the hash is in the table if true, but if either bit is false, the symbol is definitely not in the table.
///
/// We then take the symbol index to start checking from by `buckets[hash % head.nbuckets]`.
/// This may be less than `head.symoffset`. If it is `0` then the symbol is absent from the table.
/// > It is not yet know what the behaviour of symbols in `1..head.symoffset` is, or if these values are allowed to appear.
/// > The implementation in this library assumes they can appear and treats them identically to a `0` value.
///
/// The chain index is taken by subtracting `head.symoffset` from this index. The top 31 bits of this chain entry is the top 31 bits of the hash value of the corresponding symbol.
/// The hash is compared ignoring the lower bit. If they match, the symbol index can be looked up in the dynamic symbol table and a name comparison can be done.
/// If either the hash comparison or the name comparison fails, the least significant bit of the chain determines the following behavior:
/// * If the last bit is `0`, the next symbol in the bucket can be checked. This is the subsequent entry in both in the symbol table and in the chain array (unlike `DT_HASH`, a pointer is not followed).
/// * If the last bit is `1`, this is the last entry in the current bucket, and the symbol is not present in the table.
///
/// ## Symbol Table format
///
/// The support the ordering requirements set by the chain array and the bucket array, the following constraints are placed on the dynamic symbol table (accessible from `DT_SYMTAB`):
/// * All symbols in the hashtable must be contiguous,
/// * The layout of the symbols that belong to the hashtable in the symbol table exactly corresponds to the layout of the chain array, in particular:
///    * The symbols are grouped by which bucket entry they fall into and,
///    * They are ordered such that the corresponding entry in the chain array has the value corresponding to the hash of the symbol name.
///
/// Note that the requirement only applies to symbols that belong in the hashtable (which are all symbols starting from `head.symoffset`).
///
#[derive(Copy, Clone, Pod, Zeroable)]
#[repr(C)]
pub struct ElfGnuHashHeader {
    pub nbuckets: u32,
    pub symoffset: u32,
    pub bloom_size: u32,
    pub bloom_shift: u32,
}

pub const EM_HOST: consts::ElfMachine = cfg_match::cfg_match! {
    target_arch = "x86" => consts::EM_386,
    target_arch = "x86_64" => consts::EM_X86_64,
};
