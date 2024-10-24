#ifndef __KANAWHA__ELF_RELOC_H__
#define __KANAWHA__ELF_RELOC_H__

#include <elf/elf.h>
#include <elf/module.h>
#include <kanawha/module.h>
#include <kanawha/ptree.h>
#include <kanawha/stdint.h>

struct elf64_machine_reloc
{
    int(*apply)(
            struct module *mod,
            struct fs_node *node,
            struct elf64_module_state *state,
            size_t section_size,
            void *section,
            uint32_t type,
            uint32_t symbol,
            Elf64_Addr offset,
            int64_t addend);

    const char *(*get_string)(uint32_t reloc_type);

    Elf64_Half machine;

    struct ptree_node tree_node;
};

int
elf64_register_machine_reloc(struct elf64_machine_reloc *reloc);

int
elf64_apply_reloc(
        struct module *mod,
        struct fs_node *node,
        struct elf64_module_state *state,
        size_t section_size,
        void *section,
        uint32_t type,
        uint32_t symbol,
        Elf64_Addr offset,
        int64_t addend);

#endif
