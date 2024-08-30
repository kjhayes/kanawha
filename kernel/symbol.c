
#include <kanawha/symbol.h>
#include <kanawha/module.h>
#include <kanawha/init.h>
#include <kanawha/spinlock.h>
#include <kanawha/stddef.h>

static DECLARE_SPINLOCK(symbol_tree_lock);
static DECLARE_STREE(symbol_tree);

struct ksymbol*
ksymbol_get(const char *symbol)
{
    struct stree_node *node;

    spin_lock(&symbol_tree_lock);
    node = stree_get(&symbol_tree, symbol);
    if(node == NULL) {
        spin_unlock(&symbol_tree_lock);
        return NULL;
    }
    struct ksymbol *sym;
    sym = container_of(node, struct ksymbol, symbol_node);

    int refs = refcount_inc(&sym->mod->refcount);
    spin_unlock(&symbol_tree_lock);

    if(refs == 0) {
        // We couldn't get a reference to the symbol's
        // module (it might be in the process of being unloaded)
        return NULL;
    }

    return sym;
}

int
ksymbol_put(struct ksymbol *symbol)
{
    refcount_dec(&symbol->mod->refcount);
    return 0;
}

int
register_kernel_symbol(
        struct ksymbol *symbol,
        struct module *mod)
{
    dprintk("Trying to Register Kernel Symbol: \"%s\"\n",
            symbol->symbol);
    spin_lock(&symbol_tree_lock);
    symbol->mod = mod;
    symbol->symbol_node.key = symbol->symbol;
    int res = stree_insert(&symbol_tree, &symbol->symbol_node);
    spin_unlock(&symbol_tree_lock);
    return res;
}

int
unregister_kernel_symbol(
        struct ksymbol *symbol)
{
    dprintk("Trying to Unregister Kernel Symbol: \"%s\"\n",
            symbol->symbol);

    if(!refcount_reapable(&symbol->mod->refcount)) {
        // Cannot unload the symbol of a module which is not reapable
        return -EINVAL;
    }

    int res = 0;
    spin_lock(&symbol_tree_lock);
    struct stree_node *removed
        = stree_remove(&symbol_tree, symbol->symbol_node.key);
    if(removed != &symbol->symbol_node) {
        stree_insert(&symbol_tree, removed);
        res = -EINVAL;
    }
    spin_unlock(&symbol_tree_lock);
    return res;
}


