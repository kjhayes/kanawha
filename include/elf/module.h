#ifndef __KANAWHA__ELF_MODULE_STATE_H__
#define __KANAWHA__ELF_MODULE_STATE_H__

#include <elf/elf.h>
#include <kanawha/stdint.h>

struct elf64_module_state
{
    Elf64_Ehdr hdr;
    size_t phdrs_size;
    Elf64_Phdr *phdrs;
    size_t shdrs_size;
    Elf64_Shdr *shdrs;
    size_t shstrtab_size;
    void *shstrtab;
    size_t symtab_size;
    Elf64_Sym *symtab;
    size_t symstrtab_size;
    void *symstrtab;
};

#endif
