
#include <kanawha/env.h>
#include <kanawha/process.h>
#include <kanawha/spinlock.h>
#include <kanawha/string.h>
#include <kanawha/kmalloc.h>
#include <kanawha/stree.h>
#include <kanawha/assert.h>

int
environment_init_new(
        struct process *process)
{
    stree_init(&process->environ.env_table);
    spinlock_init(&process->environ_lock);
    return 0;
}

int
environment_init_inherit(
        struct process *parent,
        struct process *child)
{
    int res;

    res = environment_init_new(child);
    if(res) {
        goto err0;
    }

    spin_lock(&parent->environ_lock);

    struct stree_node *node;
    for(node = stree_get_first(&parent->environ.env_table);
        node != NULL;
        node = stree_get_next(node))
    {
        struct envvar *var =
            container_of(node, struct envvar, node);

        struct envvar *child_var = kmalloc(sizeof(struct envvar));
        if(child_var == NULL) {
            res = -ENOMEM;
            goto err2;
        }
        memset(child_var, 0, sizeof(struct envvar));

        char *key_dup = kstrdup(var->node.key);
        if(key_dup == NULL) {
            kfree(child_var);
            res = -ENOMEM;
            goto err2;
        }

        char *value_dup = kstrdup(var->value);
        if(value_dup == NULL) {
            kfree(child_var);
            kfree(key_dup);
            res = -ENOMEM;
            goto err2;
        }

        child_var->value = value_dup;
        child_var->node.key = key_dup;
        res = stree_insert(
                &child->environ.env_table,
                &child_var->node);
        if(res) {
            kfree(child_var);
            kfree(key_dup);
            kfree(value_dup);
            goto err2;
        }
    }

    spin_unlock(&parent->environ_lock);
    return 0;

err2:
    // Free any child variables we created
    environment_clear_all(child);
err1:
    spin_unlock(&parent->environ_lock);
err0:
    return res;
}


int
environment_clear_all(
        struct process *process)
{
    struct stree_node *node;

    spin_lock(&process->environ_lock);

    node = stree_get_first(&process->environ.env_table);
    while(node) {
        struct envvar *var =
            container_of(node, struct envvar, node);

        struct stree_node *rem =
            stree_remove(&process->environ.env_table, var->node.key);
        DEBUG_ASSERT(rem == node);

        kfree((void*)var->node.key);
        kfree((void*)var->value);
        kfree(var);

        node = stree_get_first(&process->environ.env_table);
    }

    spin_unlock(&process->environ_lock);
    return 0;
}

int
environment_clear_var(
        struct process *process,
        const char *var_name)
{
    spin_lock(&process->environ_lock);

    struct stree_node *node =
        stree_get(&process->environ.env_table, var_name);

    if(node != NULL) {
        struct envvar *var =
            container_of(node, struct envvar, node);

        struct stree_node *rem = stree_remove(
                &process->environ.env_table, var_name);
        DEBUG_ASSERT(rem == node);
        
        kfree((void*)var->node.key);
        kfree((void*)var->value);
        kfree((void*)var);
    }

    spin_unlock(&process->environ_lock);
    return 0;
}

int
environment_set(
        struct process *process,
        const char *var_name,
        const char *value)
{
    int res;

    spin_lock(&process->environ_lock);

    struct stree_node *node =
        stree_get(&process->environ.env_table, var_name);

    if(node == NULL)
    {
        struct envvar *var = kmalloc(sizeof(struct envvar));
        if(var == NULL) {
            spin_unlock(&process->environ_lock);
            return -ENOMEM;
        }
        memset(var, 0, sizeof(struct envvar));

        char *key_dup = kstrdup(var_name);
        if(key_dup == NULL) {
            kfree(var);
            spin_unlock(&process->environ_lock);
            return -ENOMEM;
        }
        char *value_dup = kstrdup(value);
        if(value_dup == NULL) {
            kfree(key_dup);
            kfree(var);
            spin_unlock(&process->environ_lock);
            return -ENOMEM;
        }

        var->value = value_dup;
        var->node.key = key_dup;

        res = stree_insert(
                &process->environ.env_table,
                &var->node);
        if(res) {
            kfree(value_dup);
            kfree(key_dup);
            kfree(var);
            spin_unlock(&process->environ_lock);
            return res;
        }

    } else {
        struct envvar *var =
            container_of(node, struct envvar, node);

        char *value_dup = kstrdup(value);
        if(value_dup == NULL) {
            spin_unlock(&process->environ_lock);
            return -ENOMEM;
        }

        kfree(var->value);
        var->value = value_dup;
    }

    spin_unlock(&process->environ_lock);
    return 0;
}

const char *
environment_get_var(
        struct process *process,
        const char *var_name)
{
    spin_lock(&process->environ_lock);

    struct stree_node *node =
        stree_get(
                &process->environ.env_table,
                var_name);

    if(node == NULL) {
        spin_unlock(&process->environ_lock);
        return NULL;
    }

    struct envvar *var =
        container_of(node, struct envvar, node);

    // NOTE: We don't unlock the environment on purpose here
    return var->value;
}

int
environment_put_var(
        struct process *process)
{
    // Assert we would fail if we tried locking the environment
    DEBUG_ASSERT(spin_try_lock(&process->environ_lock));

    spin_unlock(&process->environ_lock);
    return 0;
}

