
#include <elf/elf.h>
#include <elf/module.h>
#include <elf/reloc.h>
#include <elf/elf_string.h>
#include <kanawha/init.h>
#include <kanawha/stddef.h>

static DECLARE_SPINLOCK(reloc_tree_lock);
static DECLARE_PTREE(reloc_tree);

//int
//elf64_register_machine_reloc(
//        struct elf64_machine_reloc *reloc)
//{
//    uintptr_t machine_ptr = reloc->machine;
//    spin_lock(&reloc_tree_lock);
//    int res = ptree_insert(&reloc_tree, &reloc->tree_node, machine_ptr);
//    spin_unlock(&reloc_tree_lock);
//    return res;
//}
//
//int
//elf64_apply_reloc(
//        struct module *mod,
//        struct file *file,
//        struct elf64_module_state *state,
//        size_t sec_size,
//        void *sec,
//        uint32_t type,
//        uint32_t symbol,
//        Elf64_Addr offset,
//        int64_t addend)
//{
//    uintptr_t machine_ptr = state->hdr.e_machine;
//    spin_lock(&reloc_tree_lock);
//    struct ptree_node *node = ptree_get(&reloc_tree, machine_ptr);
//    spin_unlock(&reloc_tree_lock);
//
//    if(node == NULL) {
//        eprintk("Cannot find relocation information for ELF64 machine type \"%s\"\n",
//                elf_get_machine_string(state->hdr.e_machine));
//        return -EUNIMPL;
//    }
//
//    struct elf64_machine_reloc *reloc =
//        container_of(node, struct elf64_machine_reloc, tree_node);
//
//    return (*reloc->apply)(
//            mod,
//            file,
//            state,
//            sec_size,
//            sec,
//            type,
//            symbol,
//            offset,
//            addend);
//}

