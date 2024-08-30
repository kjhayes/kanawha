#ifndef __KANAWHA__ELF_TYPES_H__
#define __KANAWHA__ELF_TYPES_H__

#include <kanawha/stdint.h>

#define DECLARE_UCHAR_CONSTANTS(NAME,VALUE,...)\
    static const unsigned char NAME = VALUE;

#define DECLARE_U16_CONSTANTS(NAME,VALUE,...)\
    static const uint16_t NAME = VALUE;

#define DECLARE_U32_CONSTANTS(NAME,VALUE,...)\
    static const uint32_t NAME = VALUE;

#define DECLARE_U32_BIT_MASK_CONSTANTS(NAME,SHIFT,BITS,...)\
    static const uint32_t NAME = ((1ULL<<(uint32_t)BITS)-1)<<SHIFT;

typedef uint32_t Elf32_Addr;
typedef uint32_t Elf32_Off;
typedef uint16_t Elf32_Section;
typedef uint16_t Elf32_Versym;
typedef uint16_t Elf32_Half;
typedef int32_t  Elf32_Sword;
typedef uint32_t Elf32_Word;
typedef int64_t  Elf32_Sxword;
typedef uint64_t Elf32_Xword;

typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint16_t Elf64_Section;
typedef uint16_t Elf64_Versym;
typedef uint16_t Elf64_Half;
typedef int32_t  Elf64_Sword;
typedef uint32_t Elf64_Word;
typedef int64_t  Elf64_Sxword;
typedef uint64_t Elf64_Xword;

typedef unsigned char Elf_Byte;

#define EI_NIDENT 16

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    uint16_t      e_type;
    uint16_t      e_machine;
    uint32_t      e_version;
    Elf32_Addr     e_entry;
    Elf32_Off      e_phoff;
    Elf32_Off      e_shoff;
    uint32_t      e_flags;
    uint16_t      e_ehsize;
    uint16_t      e_phentsize;
    uint16_t      e_phnum;
    uint16_t      e_shentsize;
    uint16_t      e_shnum;
    uint16_t      e_shstrndx;
} Elf32_Ehdr;

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    uint16_t      e_type;
    uint16_t      e_machine;
    uint32_t      e_version;
    Elf64_Addr     e_entry;
    Elf64_Off      e_phoff;
    Elf64_Off      e_shoff;
    uint32_t      e_flags;
    uint16_t      e_ehsize;
    uint16_t      e_phentsize;
    uint16_t      e_phnum;
    uint16_t      e_shentsize;
    uint16_t      e_shnum;
    uint16_t      e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t   p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    uint32_t   p_filesz;
    uint32_t   p_memsz;
    uint32_t   p_flags;
    uint32_t   p_align;
} Elf32_Phdr;

typedef struct {
    uint32_t   p_type;
    uint32_t   p_flags;
    Elf64_Off  p_offset;
    Elf64_Addr p_vaddr;
    Elf64_Addr p_paddr;
    uint64_t   p_filesz;
    uint64_t   p_memsz;
    uint64_t   p_align;
} Elf64_Phdr;

typedef struct {
    uint32_t   sh_name;
    uint32_t   sh_type;
    uint32_t   sh_flags;
    Elf32_Addr sh_addr;
    Elf32_Off  sh_offset;
    uint32_t   sh_size;
    uint32_t   sh_link;
    uint32_t   sh_info;
    uint32_t   sh_addralign;
    uint32_t   sh_entsize;
} Elf32_Shdr;

typedef struct {
    uint32_t   sh_name;
    uint32_t   sh_type;
    uint64_t   sh_flags;
    Elf64_Addr sh_addr;
    Elf64_Off  sh_offset;
    uint64_t   sh_size;
    uint32_t   sh_link;
    uint32_t   sh_info;
    uint64_t   sh_addralign;
    uint64_t   sh_entsize;
} Elf64_Shdr;

enum {
    EI_MAG0 = 0,
    EI_MAG1,
    EI_MAG2,
    EI_MAG3,
    EI_CLASS,
    EI_DATA,
    EI_VERSION,
    EI_OSABI,
    EI_ABIVERSION,
    EI_PAD,
};

#define EI_MAG0_VALID 0x7f
#define EI_MAG1_VALID 'E'
#define EI_MAG2_VALID 'L'
#define EI_MAG3_VALID 'F'

#define ELFCLASS_XLIST(X)\
X(ELFCLASSNONE, 0,"Unknown")\
X(ELFCLASS32,   1,"Elf32")\
X(ELFCLASS64,   2,"Elf64")
ELFCLASS_XLIST(DECLARE_UCHAR_CONSTANTS)

#define ELFDATA_XLIST(X)\
X(ELFDATANONE, 0,"None")\
X(ELFDATA2LSB, 1,"Little-Endian")\
X(ELFDATA2MSB, 2,"Big-Endian")
ELFDATA_XLIST(DECLARE_UCHAR_CONSTANTS)

#define EV_XLIST(X)\
X(EV_NONE,    0,"None")\
X(EV_CURRENT, 1,"Current")
EV_XLIST(DECLARE_U32_CONSTANTS)

#define ELFOSABI_XLIST(X)\
X(ELFOSABI_NONE,     0,"None")\
X(ELFOSABI_HPUX,     1,"HPUX")\
X(ELFOSABI_NETBSD,   2,"NetBSD")\
X(ELFOSABI_LINUX,    3,"Linux")\
X(ELFOSABI_SOLARIS,  6,"Solaris")\
X(ELFOSABI_AIX,      7,"AIX")\
X(ELFOSABI_IRIX,     8,"IRIX")\
X(ELFOSABI_FREEBSD,  9,"FreeBSD")\
X(ELFOSABI_TRU64,   10,"TRU64")\
X(ELFOSABI_MODESTO, 11,"MODESTO")\
X(ELFOSABI_OPENBSD, 12,"OpenBSD")\
X(ELFOSABI_OPENVMS, 13,"OpenVMS")\
X(ELFOSABI_NSK,     14,"NSK")
ELFOSABI_XLIST(DECLARE_UCHAR_CONSTANTS)

#define ELFABIVERSION_XLIST(X)\
X(ELFABIVERSION_UNSPEC, 0, "Unspecified")
ELFABIVERSION_XLIST(DECLARE_UCHAR_CONSTANTS)

#define ET_XLIST(X)\
X(ET_NONE, 0, "None")\
X(ET_REL,  1, "Relocatable")\
X(ET_EXEC, 2, "Executable")\
X(ET_DYN,  3, "Dynamic")\
X(ET_CORE, 4, "Core")
ET_XLIST(DECLARE_U16_CONSTANTS)

#define EM_XLIST(X)\
X(EM_NONE,          0,"None")\
X(EM_M32,           1,"M32")\
X(EM_SPARC,         2,"SPARC")\
X(EM_386,           3,"386")\
X(EM_68K,           4,"68K")\
X(EM_88K,           5,"88K")\
X(EM_486,           6,"486")\
X(EM_860,           7,"860")\
X(EM_MIPS,          8,"MIPS")\
X(EM_MIPS_RS3_LE,  10,"MIPS_RS3_LE")\
X(EM_PARISC,       15,"PARISC")\
X(EM_SPARC32PLUS,  18,"SPARC32PLUS")\
X(EM_PPC,          20,"PowerPC")\
X(EM_PPC64,        21,"PowerPC64")\
X(EM_SPU,          23,"SPU")\
X(EM_ARM,          40,"ARM")\
X(EM_SH,           42,"SH")\
X(EM_SPARCV9,      43,"SPARCV9")\
X(EM_H8_300,       46,"H8_300")\
X(EM_IA_64,        50,"IA_64")\
X(EM_X86_64,       62,"x86_64")\
X(EM_S390,         22,"S390")\
X(EM_CRIS,         76,"CRIS")\
X(EM_M32R,         88,"M32R")\
X(EM_MN10300,      89,"MN10300")\
X(EM_OPENRISC,     92,"OPENRISC")\
X(EM_ARCOMPACT,    93,"ARCOMPACT")\
X(EM_XTENSA,       94,"XTENSA")\
X(EM_BLACKFIN,    106,"BLACKFIN")\
X(EM_UNICORE,     110,"UNICORE")\
X(EM_ALTERA_NIOS2,113,"ALTERA_NIOS2")\
X(EM_TI_C6000,    140,"TI_C6000")\
X(EM_HEXAGON,     164,"HEXAGON")\
X(EM_NDS32,       167,"NDS32")\
X(EM_AARCH64,     183,"Aarch64")\
X(EM_TILEPRO,     188,"TILEPRO")\
X(EM_MICROBLAZE,  189,"MICROBLAZE")\
X(EM_TILEGX,      191,"TILEGX")\
X(EM_ARCV2,       195,"ARCV2")\
X(EM_RISCV,       243,"CV")\
X(EM_BPF,         247,"BPF")\
X(EM_CSKY,        252,"CSKY")\
X(EM_LOONGARCH,   258,"LOONGARCH")\
X(EM_FRV,      0x5441,"FRV")
EM_XLIST(DECLARE_U16_CONSTANTS)

#define SHF_XLIST(X)\
X(SHF_WRITE,          (1ULL<<0),  "SHF_WRITE")\
X(SHF_ALLOC,          (1ULL<<1),  "SHF_ALLOC")\
X(SHF_EXECINSTR,      (1ULL<<2),  "SHF_EXECINSTR")\
X(SHF_RELA_LIVEPATCH, (1ULL<<20), "SHF_RELA_LIVEPATCH")\
X(SHF_RO_AFTER_INIT,  (1ULL<<21), "SHF_RO_AFTER_INIT")
SHF_XLIST(DECLARE_U32_CONSTANTS)

#define SHT_XLIST(X)\
X(SHT_NULL,     0x00000000, "SHT_NULL")\
X(SHT_PROGBITS, 0x00000001, "SHT_PROGBITS")\
X(SHT_SYMTAB,   0x00000002, "SHT_SYMTAB")\
X(SHT_STRTAB,   0x00000003, "SHT_STRTAB")\
X(SHT_RELA,     0x00000004, "SHT_RELA")\
X(SHT_HASH,     0x00000005, "SHT_HASH")\
X(SHT_DYNAMIC,  0x00000006, "SHT_DYNAMIC")\
X(SHT_NOTE,     0x00000007, "SHT_NOTE")\
X(SHT_NOBITS,   0x00000008, "SHT_NOBITS")\
X(SHT_REL,      0x00000009, "SHT_REL")\
X(SHT_SHLIB,    0x0000000A, "SHT_SHLIB")\
X(SHT_DYNSYM,   0x0000000B, "SHT_DYNSYM")\
X(SHT_NUM,      0x0000000C, "SHT_NUM")\
X(SHT_LOPROC,   0x70000000, "SHT_LOPROC")\
X(SHT_HIPROC,   0x7fffffff, "SHT_HIPROC")\
X(SHT_LOUSER,   0x80000000, "SHT_LOUSER")\
X(SHT_HIUSER,   0xffffffff, "SHT_HIUSER")
SHT_XLIST(DECLARE_U32_CONSTANTS)

#define SHN_XLIST(X)\
X(SHN_UNDEF,     0x0000, "SHN_UNDEF")\
X(SHN_LORESERVE, 0xFF00, "SHN_LORESERVE")\
X(SHN_LOPROC,    0xFF00, "SHN_LOPROC")\
X(SHN_HIPROC,    0xFF1F, "SHN_HIPROC")\
X(SHN_LIVEPATCH, 0xFF20, "SHN_LIVEPATCH")\
X(SHN_ABS,       0xFFF1, "SHN_ABS")\
X(SHN_COMMON,    0xFFF2, "SHN_COMMON")\
X(SHN_HIRESERVE, 0xFFFF, "SHN_HIRESERVE")
SHN_XLIST(DECLARE_U16_CONSTANTS)

// Relocation Entries

typedef struct {
    Elf32_Addr r_offset;
    uint32_t   r_info;
} Elf32_Rel;

typedef struct {
    Elf64_Addr r_offset;
    uint64_t   r_info;
} Elf64_Rel;

typedef struct {
    Elf32_Addr r_offset;
    uint32_t   r_info;
    int32_t    r_addend;
} Elf32_Rela;

typedef struct {
    Elf64_Addr r_offset;
    uint64_t   r_info;
    int64_t    r_addend;
} Elf64_Rela;



// Symbols

typedef struct {
    uint32_t      st_name;
    Elf32_Addr    st_value;
    uint32_t      st_size;
    unsigned char st_info;
    unsigned char st_other;
    uint16_t      st_shndx;
} Elf32_Sym;

typedef struct {
    uint32_t      st_name;
    unsigned char st_info;
    unsigned char st_other;
    uint16_t      st_shndx;
    Elf64_Addr    st_value;
    uint64_t      st_size;
} Elf64_Sym;

#define STB_XLIST(X)\
X(STB_LOCAL,  (0<<4), "Local")\
X(STB_GLOBAL, (1<<4), "Global")\
X(STB_WEAK,   (2<<4), "Weak")
STB_XLIST(DECLARE_UCHAR_CONSTANTS)

#define STT_XLIST(X)\
X(STT_NOTYPE,  0, "None")\
X(STT_OBJECT,  1, "Object")\
X(STT_FUNC,    2, "Function")\
X(STT_SECTION, 3, "Section")\
X(STT_FILE,    4, "File")\
X(STT_COMMON,  5, "Common")\
X(STT_TLS,     6, "Thread-Local")
STT_XLIST(DECLARE_UCHAR_CONSTANTS)

#define ELF_ST_BIND(__STB) (__STB&0xF0)
#define ELF_ST_TYPE(__STT) (__STT&0x0F)

#define STV_XLIST(X)\
X(STV_DEFAULT,   0, "Default")\
X(STV_INTERNAL,  1, "Internal")\
X(STV_HIDDEN,    2, "Hidden")\
X(STV_PROTECTED, 3, "Protected")
STV_XLIST(DECLARE_UCHAR_CONSTANTS)

#define ELF64_R_TYPE(reloc_info) (reloc_info & 0xFFFFFFFF)
#define ELF64_R_SYM(reloc_info) (reloc_info >> 32)
#define ELF64_R_INFO(sym,type) (((Elf64_Xword)sym << 32) | ((Elf64_Xword)type & 0xFFFFFFFF))

#define PT_XLIST(X)\
X(PT_NULL,    0x00000000, "NULL")\
X(PT_LOAD,    0x00000001, "LOAD")\
X(PT_DYNAMIC, 0x00000002, "DYNAMIC")\
X(PT_INTERP,  0x00000003, "INTERP")\
X(PT_NOTE,    0x00000004, "NOTE")\
X(PT_SHLIB,   0x00000005, "SHLIB")\
X(PT_PHDR,    0x00000006, "PHDR")\
X(PT_TLS,     0x00000007, "TLS")\
X(PT_LOOS,    0x60000000, "LOOS")\
X(PT_HIOS,    0x6FFFFFFF, "HIOS")\
X(PT_LOPROC,  0x70000000, "LOPROC")\
X(PT_HIPROC,  0x7FFFFFFF, "HIPROC")\
X(PT_GNU_EH_FRAME, 0x6474E550, "GNU_EH_FRAME")\
X(PT_GNU_STACK,    0x6474E551, "GNU_STACK")\
X(PT_GNU_RELRO,    0x6474E552, "GNU_RELRO")
PT_XLIST(DECLARE_U32_CONSTANTS)

#define PF_XLIST(X)\
X(PF_X, 0, 1, "Execute")\
X(PF_W, 1, 1, "Write")\
X(PF_R, 2, 1, "Read")\
X(PF_MASKOS, 20, 8, "OS")\
X(PF_MASKPROC, 28, 4, "Process")
PF_XLIST(DECLARE_U32_BIT_MASK_CONSTANTS)

#undef DECLARE_U32_BIT_MASK_CONSTANTS
#undef DECLARE_UCHAR_CONSTANTS
#undef DECLARE_U16_CONSTANTS
#undef DECLARE_U32_CONSTANTS

#endif
