#ifndef __KANAWHA__ELF_X86_64_H__
#define __KANAWHA__ELF_X86_64_H__

#include <kanawha/stdint.h>

#define DECLARE_U32_CONSTANTS(NAME, VAL, ...)\
    const static uint32_t NAME = VAL;

#define X86_64_ELF_RELOC_XLIST(X)\
X(R_X86_64_NONE,                   0)\
X(R_X86_64_64,                     1)\
X(R_X86_64_PC32,                   2)\
X(R_X86_64_GOT32,                  3)\
X(R_X86_64_PLT32,                  4)\
X(R_X86_64_COPY,                   5)\
X(R_X86_64_GLOB_DAT,               6)\
X(R_X86_64_JUMP_SLOT,              7)\
X(R_X86_64_RELATIVE,               8)\
X(R_X86_64_GOTPCREL,               9)\
X(R_X86_64_32,                     10)\
X(R_X86_64_32S,                    11)\
X(R_X86_64_16,                     12)\
X(R_X86_64_PC16,                   13)\
X(R_X86_64_8,                      14)\
X(R_X86_64_PC8,                    15)\
X(R_X86_64_DTPMOD64,               16)\
X(R_X86_64_DTPOFF64,               17)\
X(R_X86_64_TPOFF64,                18)\
X(R_X86_64_TLSGD,                  19)\
X(R_X86_64_TLSLD,                  20)\
X(R_X86_64_DTPOFF32,               21)\
X(R_X86_64_GOTTPOFF,               22)\
X(R_X86_64_TPOFF32,                23)\
X(R_X86_64_PC64,                   24)\
X(R_X86_64_GOTOFF64,               25)\
X(R_X86_64_GOTPC32,                26)\
X(R_X86_64_GOT64,                  27)\
X(R_X86_64_GOTPCREL64,             28)\
X(R_X86_64_GOTPC64,                29)\
X(R_X86_64_PLTOFF64,               31)\
X(R_X86_64_SIZE32,                 32)\
X(R_X86_64_SIZE64,                 33)\
X(R_X86_64_GOTPC32_TLSDESC,        34)\
X(R_X86_64_TLSDESC_CALL,           35)\
X(R_X86_64_TLSDESC,                36)\
X(R_X86_64_IRELATIVE,              37)\
X(R_X86_64_RELATIVE64,             38)\
X(R_X86_64_GOTPCRELX,              41)\
X(R_X86_64_REX_GOTPCRELX,          42)\
X(R_X86_64_CODE_4_GOTPCRELX,       43)\
X(R_X86_64_CODE_4_GOTTPOFF,        44)\
X(R_X86_64_CODE_4_GOTPC32_TLSDESC, 45)\
X(R_X86_64_CODE_5_GOTPCRELX,       46)\
X(R_X86_64_CODE_5_GOTTPOFF,        47)\
X(R_X86_64_CODE_5_GOTPC32_TLSDESC, 48)\
X(R_X86_64_CODE_6_GOTPCRELX,       49)\
X(R_X86_64_CODE_6_GOTTPOFF,        50)\
X(R_X86_64_CODE_6_GOTPC32_TLSDESC, 51)
X86_64_ELF_RELOC_XLIST(DECLARE_U32_CONSTANTS)

#undef DECLARE_U32_CONSTANTS

#endif
