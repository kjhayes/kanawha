
#include <elf/x86_64.h>
#include <elf/module.h>
#include <elf/reloc.h>
#include <kanawha/symbol.h>
#include <kanawha/init.h>

//static
//const char *
//x86_64_elf64_get_reloc_string(
//        uint32_t reloc_type)
//{
//    const char *ret = "Unknown";
//    switch(reloc_type) {
//#define HANDLE_CASE(NAME, ...)\
//        case NAME: ret = #NAME; break;
//X86_64_ELF_RELOC_XLIST(HANDLE_CASE)
//#undef HANDLE_CASE
//    }
//    return ret;
//}
//
//
//static int
//x86_64_elf64_apply(
//        struct module *mod,
//        struct file *file,
//        struct elf64_module_state *state,
//        size_t section_size,
//        void *section,
//        uint32_t type,
//        uint32_t symbol_index,
//        Elf64_Addr offset,
//        int64_t addend)
//{
//    switch(type) {
//        case R_X86_64_8:
//        case R_X86_64_PC8:
//        case R_X86_64_16:
//        case R_X86_64_PC16:
//            eprintk("Tried to apply deprecated relocation type (%s)\n",
//                    x86_64_elf64_get_reloc_string(type));
//            return -EINVAL;
//    }
//
//    switch(type) {
//        case R_X86_64_DTPMOD64:
//        case R_X86_64_DTPOFF64:
//        case R_X86_64_TPOFF64:
//        case R_X86_64_TLSGD:
//        case R_X86_64_TLSLD:
//        case R_X86_64_DTPOFF32:
//        case R_X86_64_GOTTPOFF:
//        case R_X86_64_TPOFF32:
//            eprintk("Tried to apply TLS relocation type (%s)\n",
//                    x86_64_elf64_get_reloc_string(type));
//            return -EINVAL;
//    }
//
//    int need_symbol = 0;
//    switch(type) {
//        case R_X86_64_64:
//        case R_X86_64_PC32:
//        case R_X86_64_GLOB_DAT:
//        case R_X86_64_JUMP_SLOT:
//        case R_X86_64_32:
//        case R_X86_64_32S:
//        case R_X86_64_16:
//        case R_X86_64_PC16:
//        case R_X86_64_8:
//        case R_X86_64_PC8:
//        case R_X86_64_PC64:
//        case R_X86_64_GOTOFF64:
//            need_symbol = 1;
//            break;
//        default:
//            need_symbol = 0;
//            break;
//    }
//
//    Elf64_Addr symbol_value;
//    uint64_t symbol_size;
//    if(need_symbol) {
//        Elf64_Sym *symbol = NULL;
//        size_t num_symbols = state->symtab_size / sizeof(Elf64_Sym);
//        if(symbol_index >= num_symbols) {
//            eprintk("Relocation referred to non-existant symbol index 0x%lx (%s)\n",
//                    symbol_index, x86_64_elf64_get_reloc_string(type));
//            return -EINVAL;
//        }
//        symbol = &state->symtab[symbol_index];
//
//        symbol_size = symbol->st_size;
//
//        struct ksymbol *ksymbol;
//        switch(symbol->st_shndx) {
//            case SHN_ABS:
//                symbol_value = symbol->st_value;
//                break;
//            case SHN_UNDEF:
//                // We need to lookup the kernel symbol
//                ksymbol = module_link_symbol(
//                        mod,
//                        (char*)(state->symstrtab + symbol->st_name));
//                if(ksymbol == NULL) {
//                    eprintk("Failed to get kernel symbol \"%s\" needed when resolving module relocations!\n",
//                            (char*)(state->symstrtab + symbol->st_name));
//                    return -ENXIO;
//                }
//                symbol_value = ksymbol->value;
//                break;
//            case SHN_COMMON:
//                eprintk("Cannot handle COMMON symbol \"%s\" in relocation!\n",
//                        (char*)(state->symstrtab + symbol->st_name));
//                return -EINVAL;
//            default:
//                if(state->hdr.e_shnum <= symbol->st_shndx) {
//                    eprintk("Symbol refers to section index %u during relocation, which does not exist!\n",
//                            symbol->st_shndx);
//                    return -EINVAL;
//                }
//                Elf64_Shdr *shdr = &state->shdrs[symbol->st_shndx];
//                if(!(shdr->sh_flags & SHF_ALLOC)) {
//                    eprintk("Cannot handle relocation to symbol in non-SHF_ALLOC section! symbol=\"%s\", section=\"%s\"\n",
//                            (char*)(state->symstrtab + symbol->st_name),
//                            (char*)(state->shstrtab + shdr->sh_name));
//                }
//                symbol_value = shdr->sh_addr + symbol->st_value;
//                break;
//        }
//    }
//
//    int res;
//
//#define __S (symbol_value)
//#define __A (addend)
//#define __P ((uintptr_t)(section + offset))
//
//    switch(type) { 
//
//        case R_X86_64_NONE:
//            res = 0;
//            break;
//
//        case R_X86_64_64:
//            if((uintptr_t)(offset + 8) > (uintptr_t)(section_size)) {
//                // Can't fit
//                eprintk("Relocation %s would overflow the section!\n",
//                        x86_64_elf64_get_reloc_string(type));
//                res = -EINVAL;
//            } else {
//                *(uint64_t*)(section + offset) =
//                    (uint64_t)(__S + __A);
//                res = 0;
//            }
//            break;
//
//        case R_X86_64_PC64:
//            if((uintptr_t)(offset + 8) > (uintptr_t)(section_size)) {
//                // Can't fit
//                eprintk("Relocation %s would overflow the section!\n",
//                        x86_64_elf64_get_reloc_string(type));
//                res = -EINVAL;
//            } else {
//                *(uint64_t*)(section + offset) =
//                    (uint64_t)(__S + __A - __P);
//                res = 0;
//            }
//            break;
//
//        default:
//            eprintk("x86_64_elf64_apply(%s) is unimplemented\n",
//                x86_64_elf64_get_reloc_string(type));
//            res = -EUNIMPL;
//            break;
//    } 
//    return res;
//
//#undef __S
//#undef __A
//#undef __P
//}
//
//static struct elf64_machine_reloc
//x86_64_elf64_relocs = {
//    .machine = EM_X86_64,
//    .apply = x86_64_elf64_apply,
//    .get_string = x86_64_elf64_get_reloc_string,
//};
//
//static int
//x86_64_register_elf_relocs(void)
//{
//    return elf64_register_machine_reloc(&x86_64_elf64_relocs);
//}
//declare_init_desc(fs, x86_64_register_elf_relocs, "Registering x64 Elf Relocation Information");

