
#include <kanawha/init.h>
#include <kanawha/lock.h>
#include <kanawha/module.h>
#include <kanawha/stddef.h>
#include <kanawha/symbol.h>

static DECLARE_STREE(symbol_tree);
DEFINE_LOCAL_THREAD_LOCK(symbol_tree_lock);

struct ksymbol *
ksymbol_get(const char *symbol)
{
    struct stree_node *node;

    symbol_tree_lock_acquire();
    node = stree_get(&symbol_tree, symbol);
    if(node == NULL)
    {
        symbol_tree_lock_release();
        return NULL;
    }
    struct ksymbol *sym;
    sym = container_of(node, struct ksymbol, symbol_node);

    int refs = refcount_inc(&sym->mod->refcount);
    symbol_tree_lock_release();

    if(refs == 0)
    {
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
register_kernel_symbol(struct ksymbol *symbol, struct module *mod)
{
    dprintk("Trying to Register Kernel Symbol: \"%s\"\n", symbol->symbol);
    symbol_tree_lock_acquire();
    symbol->mod = mod;
    symbol->symbol_node.key = symbol->symbol;
    int res = stree_insert(&symbol_tree, &symbol->symbol_node);
    symbol_tree_lock_release();
    return res;
}

int
unregister_kernel_symbol(struct ksymbol *symbol)
{
    dprintk("Trying to Unregister Kernel Symbol: \"%s\"\n", symbol->symbol);

    if(!refcount_reapable(&symbol->mod->refcount))
    {
        // Cannot unload the symbol of a module which is not reapable
        return -EINVAL;
    }

    int res = 0;
    symbol_tree_lock_acquire();
    struct stree_node *removed =
        stree_remove(&symbol_tree, symbol->symbol_node.key);
    if(removed != &symbol->symbol_node)
    {
        stree_insert(&symbol_tree, removed);
        res = -EINVAL;
    }
    symbol_tree_lock_release();
    return res;
}
