
#include <kanawha/module.h>
#include <kanawha/kmalloc.h>
#include <kanawha/stddef.h>
#include <kanawha/stree.h>
#include <kanawha/spinlock.h>
#include <kanawha/init.h>
#include <kanawha/printk.h>
#include <kanawha/symbol.h>
#include <kanawha/kmalloc.h>
#include <kanawha/arch.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/mount.h>
#include <kanawha/stdint.h>
#include <kanawha/errno.h>
#include <kanawha/string.h>
#include <elf/elf.h>
#include <elf/module.h>
#include <elf/reloc.h>
#include <elf/elf_string.h>

static spinlock_t module_tree_lock;
static struct stree module_tree;
static struct module __core_kernel_module;

static struct module *
__alloc_module_struct(void)
{
    return (struct module*)kmalloc(sizeof(struct module));
}

static void
__free_module_struct(struct module *mod)
{
    kfree(mod);
}

// Keeps a reference to name
static int
__init_module(struct module *module,
              const char *name,
              unsigned long flags)
{
    int res;
    module->name = name;
    module->tree_node.key = name;
    module->flags = flags;

    refcount_init(&module->refcount);
    spinlock_init(&module->lock);

    spin_lock(&module_tree_lock);
    res = stree_insert(&module_tree, &module->tree_node);
    spin_unlock(&module_tree_lock);

    ptree_init(&module->dependency_tree);

    if(res) {
        return res;
    }

    return 0;
}

static int
load_builtin_ksymbols(void)
{
    extern struct ksymbol __ksymtab_start[];
    extern struct ksymbol __ksymtab_end[];
    size_t num_symbols = ((void*)__ksymtab_end - (void*)__ksymtab_start) / sizeof(struct ksymbol);
    dprintk("Kernel has %lu builtin symbols\n", (unsigned long)num_symbols);

    for(size_t i = 0; i < num_symbols; i++) {
        struct ksymbol *sym = &__ksymtab_start[i];
        int res = register_kernel_symbol(sym, core_kernel_module());
        if(res) {
            eprintk("Failed to register builtin kernel symbol \"%s\" (err=%s)\n",
                    sym->symbol, errnostr(res));
            return res;
        }
    }

    return 0;
}

struct ksymbol *
module_link_symbol(
        struct module *mod,
        const char *name)
{
    struct ksymbol *sym = ksymbol_get(name);
    if(sym == NULL) {
        eprintk("Failed to link module symbol which does not exist: \"%s\"\n",
                name);
        return sym;
    }

    struct module *owner = sym->mod;

    spin_lock(&mod->lock);
    struct ptree_node *dep_node = ptree_get(&mod->dependency_tree, (uintptr_t)owner);

    if(dep_node != NULL) {
        // The dependency already exists,
        // decrement "put" the symbol to avoid extra
        // refs to the owning module

        // This looks bad, but if we maintain dependencies correctly,
        // the symbol should be gaurenteed to still exist even if we
        // "put" it.
        ksymbol_put(sym);
    } else {
        // We need to add the owning module to our dependency tree,
        struct module_dependency *dep = kmalloc(sizeof(struct module_dependency));
        if(dep == NULL) {
            eprintk("Failed to allocate module dependency struct during module_link_symbol!\n");
            ksymbol_put(sym);
            sym = NULL;
        } else {
            memset(dep, 0, sizeof(struct module_dependency));
            dep->mod = owner;
            dep->tree_node.key = (uintptr_t)owner;
            ptree_insert(&mod->dependency_tree, &dep->tree_node, (uintptr_t)owner);
        }
    }
    spin_unlock(&mod->lock);
    return sym;
}

static int
module_framework_init(void)
{
    spinlock_init(&module_tree_lock);
    stree_init(&module_tree);
    int res = __init_module(&__core_kernel_module,
                  "kanawha",
                  MODULE_FLAG_FIXED);
    if(res) {
        return res;
    }
    refcount_inc(&__core_kernel_module.refcount);
    
    res = load_builtin_ksymbols();
    if(res) {
        return res;
    }

    return 0;
}
declare_init(static, module_framework_init);

struct module *
core_kernel_module(void)
{
    return &__core_kernel_module;
}

struct module *
module_get(const char *name)
{
    int res;
    struct module *mod;
    struct stree_node *node;

    spin_lock(&module_tree_lock);
    node = stree_get(&module_tree, name);
    spin_unlock(&module_tree_lock);

    if(node == NULL) {
        return NULL;
    }
    mod = container_of(node, struct module, tree_node);

    res = refcount_inc(&mod->refcount);
    if(res) {
        return NULL;
    }
    return mod;
}

int
module_put(struct module *mod)
{
    int res;
    refcount_dec(&mod->refcount);
    res = refcount_euthanize(&mod->refcount);
    if(res) {
        // Unload the module
        // TODO
        return -EUNIMPL;
    }
    return 0;
}

static int
elf64_check_header(
        Elf64_Ehdr *hdr)
{
    if(hdr->e_ident[EI_MAG0] != EI_MAG0_VALID) {
        eprintk("ELF64 File has invalid EI_MAG0!\n");
        return -EINVAL;
    }
    if(hdr->e_ident[EI_MAG1] != EI_MAG1_VALID) {
        eprintk("ELF64 File has invalid EI_MAG1!\n");
        return -EINVAL;
    }
    if(hdr->e_ident[EI_MAG2] != EI_MAG2_VALID) {
        eprintk("ELF64 File has invalid EI_MAG2!\n");
        return -EINVAL;
    }
    if(hdr->e_ident[EI_MAG3] != EI_MAG3_VALID) {
        eprintk("ELF64 File has invalid EI_MAG3!\n");
        return -EINVAL;
    }

    if(hdr->e_ident[EI_CLASS] != ELFCLASS64) {
        eprintk("ELF File is not 64-bit!\n");
        return -EINVAL;
    }

    if(hdr->e_entry != 0) {
        eprintk("ELF64 File has an entry point!\n");
        return -EINVAL;
    }

    if(hdr->e_type != ET_REL) {
        eprintk("ELF64 File has type = \"%s\"!\n", elf_get_type_string(hdr->e_type));
        return -EINVAL;
    }

    return 0;
}

//static int
//elf64_load_module_alloc_sections(
//        struct module *mod,
//        struct file *file,
//        struct elf64_module_state *state)
//{
//    mod->section_count = 0;
//    for(size_t i = 0; i < state->hdr.e_shnum; i++) {
//        Elf64_Shdr *shdr = &state->shdrs[i];
//        if(shdr->sh_type == SHT_NULL) {
//            continue;
//        }
//        if(shdr->sh_flags & SHF_ALLOC) {
//            mod->section_count++;
//        }
//    }
//    if(mod->section_count == 0) {
//        eprintk("Module has no loadable sections? (aborting)\n");
//        return -EINVAL;
//    }
//
//    mod->sections = kmalloc(sizeof(struct module_section) * mod->section_count);
//    if(mod->sections == NULL && mod->section_count > 0) {
//        eprintk("Failed to allocate module memory section table!\n");
//        return -ENOMEM;
//    }
//    memset(mod->sections, 0, sizeof(struct module_section) * mod->section_count);
//
//    size_t sections_initialized = 0;
//    for(size_t i = 0; i < state->hdr.e_shnum; i++) {
//        Elf64_Shdr *shdr = &state->shdrs[i];
//        if(shdr->sh_type == SHT_NULL || !(shdr->sh_flags & SHF_ALLOC)) {
//            continue;
//        }
//        struct module_section *sec = &mod->sections[sections_initialized];
//        sections_initialized++;
//
//        sec->size = shdr->sh_size;
//        sec->data = kmalloc(sec->size);
//        if(sec->data == NULL) {
//            eprintk("Failed to allocate space for SHF_ALLOC section \"%s\", size=0x%lx\n",
//                    (char*)(state->shstrtab + shdr->sh_name), sec->size);
//            for(size_t unmap_i = 0; unmap_i < sections_initialized-1; unmap_i++) {
//                kfree(mod->sections[unmap_i].data);
//            }
//            return -ENOMEM;
//        }
//
//        if(shdr->sh_type == SHT_NOBITS) {
//            memset(sec->data, 0, sec->size);
//        } else {
//            file_seek(file, shdr->sh_offset, FILE_SEEK_ABS);
//            size_t read = file_read(file, sec->data, sec->size);
//            if(read != sec->size) {
//                eprintk("Failed to read data from SHF_ALLOC section \"%s\", size=0x%lx\n",
//                        (char*)(state->shstrtab + shdr->sh_name), sec->size);
//                for(size_t unmap_i = 0; unmap_i < sections_initialized; unmap_i++) {
//                    kfree(mod->sections[unmap_i].data);
//                }
//                return -EINVAL;
//            }
//        }
//
//        // Mark the address in the temporary section header structure
//        // (Will be used when resolving relocations)
//        shdr->sh_addr = (uintptr_t)sec->data;
//
//        dprintk("Loaded Section: \"%s\" size=0x%lx\n",
//                (char*)(state->shstrtab + shdr->sh_name), sec->size);
//    }
//    if(sections_initialized != mod->section_count) {
//        eprintk("Section count mismatch? (initialized=%d, sections=%d)\n",
//                sections_initialized, mod->section_count);
//        for(size_t unmap_i = 0; unmap_i < sections_initialized; unmap_i++) {
//            kfree(mod->sections[unmap_i].data);
//        }
//        return -EINVAL;
//    }
//
//    return 0;
//}
//
//static int
//elf64_handle_reloc_section(
//        struct module *mod,
//        struct file *file,
//        struct elf64_module_state *state,
//        Elf64_Shdr *shdr)
//{
//    int res;
//
//    size_t entry_size = 0;
//    switch(shdr->sh_type) {
//        case SHT_REL:
//            entry_size = sizeof(Elf64_Rel);
//            break;
//        case SHT_RELA:
//            entry_size = sizeof(Elf64_Rela);
//            break;
//        default:
//            eprintk("Passed non SHT_REL or SHT_RELA section to elf64_handle_reloc_section!\n");
//            return -EINVAL;
//    }
//
//    size_t num_rel = shdr->sh_size / entry_size;
//    if(num_rel == 0) {
//        eprintk("Found Relocation section with zero entries? (ignoring)\n");
//        return 0;
//    }
//
//    size_t target_shndx = shdr->sh_info;
//
//    switch(target_shndx) {
//        case SHN_UNDEF:
//            eprintk("Found Relocation section referring to SHN_UNDEF!\n");
//            return -EINVAL;
//        case SHN_ABS:
//            eprintk("Found Relocation section referring to SHN_ABS!\n");
//            return -EINVAL;
//        case SHN_COMMON:
//            eprintk("Found Relocation section referring to SHN_COMMON!\n");
//            return -EINVAL;
//    }
//
//    Elf64_Shdr *target_hdr = &state->shdrs[target_shndx];
//
//    if(!(target_hdr->sh_flags & SHF_ALLOC)) {
//        dprintk("Ignoring relocation section for section without SHF_ALLOC flag\n");
//        dprintk("Relocation Section: \"%s\" Target: \"%s\"\n",
//                (const char*)(state->shstrtab + shdr->sh_name),
//                (const char*)(state->shstrtab + target_hdr->sh_name));
//        return 0;
//    }
//
//    void *sec_data = (void*)target_hdr->sh_addr;
//    size_t sec_size = target_hdr->sh_size;
//
//    void *rel_data = kmalloc(shdr->sh_size);
//    if(rel_data == NULL) {
//        res = -ENOMEM;
//        goto exit0;
//    }
//    file_seek(file, shdr->sh_offset, FILE_SEEK_ABS);
//    size_t read = file_read(file, rel_data, shdr->sh_size);
//    if(read != shdr->sh_size) {
//        eprintk("Failed to read SHT_REL section!\n");
//        res = -EINVAL;
//        goto exit1;
//    }
//
//    for(size_t i = 0; i < num_rel; i++) {
//
//        uint32_t type;
//        uint32_t symbol;
//        Elf64_Addr offset;
//        int64_t addend;
//
//        if(shdr->sh_type == SHT_REL) {
//            Elf64_Rel *rel = &((Elf64_Rel*)rel_data)[i];
//            type = ELF64_R_TYPE(rel->r_info);
//            symbol = ELF64_R_SYM(rel->r_info);
//            offset = rel->r_offset;
//            addend = 0;
//        } else { //SHT_RELA
//            Elf64_Rela *rela = &((Elf64_Rela*)rel_data)[i];
//            type = ELF64_R_TYPE(rela->r_info);
//            symbol = ELF64_R_SYM(rela->r_info);
//            offset = rela->r_offset;
//            addend = rela->r_addend;
//        }
//
//        res = elf64_apply_reloc(
//                mod,
//                file,
//                state,
//                sec_size,
//                sec_data,
//                type,
//                symbol,
//                offset,
//                addend);
//
//        if(res) {
//            eprintk("Failed to resolve Elf64 Relocation!\n");
//            goto exit1;
//        }
//    }
//
//
//    res = 0;
//exit1:
//    kfree(rel_data);
//exit0:
//    return res;
//}
//
//static int
//elf64_load_module_reloc(
//        struct module *mod,
//        struct file *file,
//        struct elf64_module_state *state)
//{
//    int res;
//
//    for(size_t i = 0; i < state->hdr.e_shnum; i++) {
//        Elf64_Shdr *shdr = &state->shdrs[i];
//
//        if(shdr->sh_type == SHT_REL || shdr->sh_type == SHT_RELA) {
//            res = elf64_handle_reloc_section(
//                    mod,
//                    file,
//                    state,
//                    shdr);
//            if(res) {
//                eprintk("Failed to resolve module relocation section!\n");
//                return res;
//            }
//        }
//    }
//
//    return 0;
//}
//
//static int
//elf64_load_module_read_hdrs(
//        struct file *file,
//        struct elf64_module_state *state)
//{
//    int res;
//    size_t read;
//
//    state->phdrs_size = state->hdr.e_phentsize * state->hdr.e_phnum;
//    state->phdrs = kmalloc(state->phdrs_size);
//    if(state->phdrs == NULL && state->hdr.e_phnum > 0) {
//        res = -ENOMEM;
//        goto err0;
//    }
//    file_seek(file, state->hdr.e_phoff, FILE_SEEK_ABS);
//    read = file_read(file, state->phdrs, state->phdrs_size);
//    if(read != state->phdrs_size) {
//        eprintk("Failed to read ELF Program Header Table!\n");
//        res = -EINVAL;
//        goto err1;
//    }
//
//    state->shdrs_size = state->hdr.e_shentsize * state->hdr.e_shnum;
//    state->shdrs = kmalloc(state->shdrs_size);
//    if(state->shdrs == NULL && state->hdr.e_shnum > 0) {
//        res = -ENOMEM;
//        goto err1;
//    }
//    file_seek(file, state->hdr.e_shoff, FILE_SEEK_ABS);
//    read = file_read(file, state->shdrs, state->shdrs_size);
//    if(read != state->shdrs_size) {
//        eprintk("Failed to read ELF Section Header Table!\n");
//        res = -EINVAL;
//        goto err2;
//    }
//
//    if(state->hdr.e_shnum <= 0) {
//        eprintk("Module must have at least 1 section!\n");
//        res = -EINVAL;
//        goto err2;
//    }
//
//    return 0;
//
//err2:
//    kfree(state->phdrs);
//err1:
//    kfree(state->phdrs);
//err0:
//    return res;
//}
//
//static int
//elf64_load_module_read_tables(
//        struct file *file,
//        struct elf64_module_state *state)
//{
//    int res;
//    size_t read;
//
//    // Read Section Header String Table
//    Elf64_Shdr *shstrtab_hdr = &state->shdrs[state->hdr.e_shstrndx];
//    state->shstrtab_size = shstrtab_hdr->sh_size;
//    state->shstrtab = kmalloc(state->shstrtab_size);
//    if(state->shstrtab == NULL) {
//        res = -ENOMEM;
//        goto err0;
//    }
//    file_seek(file, shstrtab_hdr->sh_offset, FILE_SEEK_ABS);
//    read = file_read(file, state->shstrtab, state->shstrtab_size);
//    if(read != state->shstrtab_size) {
//        eprintk("Failed to read ELF String Table!\n");
//        res = -EINVAL;
//        goto err1;
//    }
//
//    // Find and Read the Symbol Table
//    Elf64_Shdr *symtab_hdr;
//    for(size_t i = 0; i < state->hdr.e_shnum; i++) {
//        symtab_hdr = &state->shdrs[i];
//        if(symtab_hdr->sh_type == SHT_SYMTAB) {
//            break;
//        }
//    }
//    if(symtab_hdr->sh_type != SHT_SYMTAB) {
//        eprintk("Could not find module ELF symbol table!\n");
//        res = -EINVAL;
//        goto err1;
//    }
//
//    state->symtab_size = symtab_hdr->sh_size;
//    state->symtab = kmalloc(state->symtab_size);
//    if(state->symtab == NULL) {
//        res = -ENOMEM;
//        goto err1;
//    }
//    file_seek(file, symtab_hdr->sh_offset, FILE_SEEK_ABS);
//    read = file_read(file, state->symtab, state->symtab_size);
//    if(read != state->symtab_size) {
//        res = -EINVAL;
//        goto err2;
//    }
//
//    // Load the Symbol Table String Section
//    if(symtab_hdr->sh_link != SHN_UNDEF) {
//        Elf64_Shdr *symstrtab_hdr = &state->shdrs[symtab_hdr->sh_link];
//        if(symstrtab_hdr->sh_type != SHT_STRTAB) {
//            eprintk("ELF Module symbol table links to a non-STRTAB section!\n");
//            res = -EINVAL;
//            goto err2;
//        }
//        state->symstrtab_size = symstrtab_hdr->sh_size;
//        state->symstrtab = kmalloc(state->symstrtab_size);
//        if(state->symstrtab == NULL) {
//            res = -ENOMEM;
//            goto err2;
//        }
//        file_seek(file, symstrtab_hdr->sh_offset, FILE_SEEK_ABS);
//        read = file_read(file, state->symstrtab, state->symstrtab_size);
//        if(read != state->symstrtab_size) {
//            eprintk("Failed to read module ELF symbol table string section!\n");
//            res = -EINVAL;
//            goto err3;
//        }
//    } else {
//        state->symstrtab = NULL;
//        state->symstrtab_size = 0;
//    }
//
//    return 0;
//
//err3:
//    kfree(state->symstrtab);
//err2:
//    kfree(state->symtab);
//err1:
//    kfree(state->shstrtab);
//err0:
//    return res;
//}
//
//static int
//elf64_load_module_run_init_section(
//        struct module *mod,
//        struct file *file,
//        struct elf64_module_state *state,
//        const char *section_name,
//        const char *init_stage_name)
//{
//    dprintk("Trying to run init section: %s\n",
//            section_name);
//    for(size_t i = 0; i < state->hdr.e_shnum; i++) {
//        Elf64_Shdr *shdr = &state->shdrs[i];
//        if(shdr->sh_type == SHT_NULL) {
//            continue;
//        }
//        char *name = state->shstrtab + shdr->sh_name;
//        dprintk("Checking %s with %s\n", name, section_name);
//        if(strcmp(name, section_name) != 0) {
//            continue;
//        }
//        // Found it!
//        if(!(shdr->sh_flags & SHF_ALLOC)) {
//            eprintk("Found init stage section \"%s\" without SHF_ALLOC set!\n");
//            return -EINVAL;
//        }
//        dprintk("Running Module init stage section: \"%s\"\n", name);
//        struct init_stage_event *events = (void*)shdr->sh_addr;
//        size_t num_events = shdr->sh_size / sizeof(struct init_stage_event);
//
//        return handle_init_stage_generic(
//                init_stage_name,
//                num_events,
//                events);
//    }
//
//    return 0; // It just doesn't exist
//}
//
//static int
//elf64_load_module_run_init_stages(
//        struct module *mod,
//        struct file *file,
//        struct elf64_module_state *state)
//{
//    int res;
//
//#define RUN_MODULE_INIT_STAGE(__stage)\
//    res = elf64_load_module_run_init_section(\
//            mod, file, state, \
//            ".kinit." #__stage ".init", \
//            #__stage);\
//    if(res) {\
//        eprintk("Failed to handle module init stage: \"" #__stage "\" (err=%s)\n",\
//                errnostr(res));\
//        return res;\
//    }
//
//XFOR_INIT_STAGE(RUN_MODULE_INIT_STAGE)
//#undef RUN_MODULE_INIT_STAGE
//
//    return res;
//}
//
//static int
//elf64_load_module(
//        struct module *mod,
//        struct file *file)
//{
//    int res;
//    struct elf64_module_state state;
//    size_t read = file_read(file, &state.hdr, sizeof(state.hdr));
//    if(read != sizeof(state.hdr)) {
//        res = -EINVAL;
//        goto exit0;
//    }
//
//    res = elf64_check_header(&state.hdr);
//    if(res) {
//        eprintk("ELF64 file has invalid header!\n");
//        goto exit0;
//    }
//
//    dprintk("Class = \"%s\"\n", elf_get_class_string(state.hdr.e_ident[EI_CLASS]));
//    dprintk("Data = \"%s\"\n", elf_get_data_string(state.hdr.e_ident[EI_DATA]));
//    dprintk("Version = \"%s\"\n", elf_get_version_string(state.hdr.e_ident[EI_VERSION]));
//    dprintk("OS ABI = \"%s\"\n", elf_get_osabi_string(state.hdr.e_ident[EI_OSABI]));
//    dprintk("ABI Version = \"%s\"\n", elf_get_abi_version_string(state.hdr.e_ident[EI_ABIVERSION]));
//    dprintk("Type = \"%s\"\n", elf_get_type_string(state.hdr.e_type));
//    dprintk("Machine = \"%s\"\n", elf_get_machine_string(state.hdr.e_machine));
//
//    arch_t arch = ARCH_UNKNOWN;
//    switch(state.hdr.e_machine) {
//        case EM_X86_64: arch = ARCH_X64; break;
//        case EM_386:    arch = ARCH_X86; break;
//    }
//
//    endian_t endian = ENDIAN_UNKNOWN;
//    switch(state.hdr.e_ident[EI_DATA]) {
//        case ELFDATA2LSB: endian = ENDIAN_LITTLE; break;
//        case ELFDATA2MSB: endian = ENDIAN_BIG; break;
//    }
//
//    res = elf64_load_module_read_hdrs(
//            file, &state);
//    if(res) {
//        goto exit0;
//    }
//
//    res = elf64_load_module_read_tables(
//            file, &state);
//    if(res) {
//        goto exit1;
//    }
//
//    // Allocate room for and load the module into memory 
//    res = elf64_load_module_alloc_sections(
//            mod,
//            file,
//            &state);
//    if(res) {
//        eprintk("Failed to handle module SHF_ALLOC sections! (err=%s)\n",
//                errnostr(res));
//        goto exit2;
//    }
//
//    // Now we need to deal with relocations
//    res = elf64_load_module_reloc(
//            mod,
//            file,
//            &state);
//    if(res) {
//        eprintk("Failed to resolve all module relocations! (err=%s)\n",
//                errnostr(res));
//
//        // We need to free the sections we allocated
//        // in elf64_load_module_alloc_sections
//        for(size_t i = 0; i < mod->section_count; i++) {
//            kfree(mod->sections[i].data);
//        }
//
//        goto exit2;
//    }
//
//    // Run .kinit functions
//    res = elf64_load_module_run_init_stages(
//            mod,
//            file,
//            &state);
//    if(res) {
//        eprintk("Failed to run module init functions! (err=%s)\n",
//                errnostr(res));
//
//        // We need to free the sections we allocated
//        // in elf64_load_module_alloc_sections
//        for(size_t i = 0; i < mod->section_count; i++) {
//            kfree(mod->sections[i].data);
//        }
//
//        goto exit2;
//    }
//
//
//    // We made it!
//    res = 0;
//
//    // These are "exits" not necessarily errors
//exit2:
//    kfree(state.symstrtab);
//    kfree(state.shstrtab);
//    kfree(state.symtab);
//exit1:
//    kfree(state.shdrs);
//    kfree(state.phdrs);
//exit0:
//    return res;
//}


//struct module *
//load_module(struct file *module_file)
//{
//    struct module *mod = kmalloc(sizeof(struct module));
//    if(mod == NULL) {
//        return mod;
//    }
//    memset(mod, 0, sizeof(struct module));
//
//    int res = elf64_load_module(mod, module_file);
//    if(res) {
//        kfree(mod);
//        return NULL;
//    }
//
//    // TODO: Export module symbols
//
//    return mod;
//}
//
//int
//unload_module(struct module *mod)
//{
//    return -EUNIMPL;
//}

