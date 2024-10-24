#ifndef __KANAWHA__MODULE_H__
#define __KANAWHA__MODULE_H__

#include <kanawha/refcount.h>
#include <kanawha/stree.h>
#include <kanawha/fs/node.h>
#include <kanawha/vmem.h>

#define MODULE_FLAG_FIXED (1ULL<<0) // This module cannot be unloaded

struct module_section
{
    size_t size;
    void *data;
};

struct module_dependency {
    struct module *mod;
    struct ptree_node tree_node;
};

struct module
{
    const char *name;
    unsigned long flags;

    refcount_t refcount; 
    spinlock_t lock;

    size_t symtab_count;
    struct ksymbol *symtab;

    size_t section_count;
    struct module_section *sections;

    struct stree_node tree_node;
    struct ptree dependency_tree;
};

struct module *
core_kernel_module(void);

// Find and increase the reference count of a module
// Returns NULL on failure
struct module *
module_get(const char *name);
// Decrease the reference count and unload if no references are left
// returns 0 on success
int
module_put(struct module *mod);

struct module *
load_module(
        struct fs_node *module_node,
        const char *name,
        unsigned long flags);
int
unload_module(struct module *mod);

// Creates a link from the module to a kernel symbol,
// can also create a dependency from "mod" to the module
// which owns "symbol"
struct ksymbol *
module_link_symbol(
        struct module *mod,
        const char *symbol);

// Check if "dependant" depends on "other"
// Returns 1 if dependency exists, 0 if not
int
check_module_dependency(
        struct module *dependant,
        struct module *other);

#endif
