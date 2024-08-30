#ifndef __KANAWHA__SYMBOL_H__
#define __KANAWHA__SYMBOL_H__

#include <kanawha/stdint.h>
#include <kanawha/refcount.h>
#include <kanawha/list.h>
#include <kanawha/stree.h>

struct module;

struct ksymbol
{
    const char *symbol;
    uintptr_t value;

    struct module *mod;
    struct stree_node symbol_node;
};

struct ksymbol*
ksymbol_get(const char *symbol);

int
ksymbol_put(struct ksymbol *symbol);

int
register_kernel_symbol(
        struct ksymbol *symbol,
        struct module *mod);

int
unregister_kernel_symbol(struct ksymbol *symbol);

#endif
