
#include <kanawha/env.h>
#include <kanawha/process.h>
#include <kanawha/spinlock.h>
#include <kanawha/string.h>
#include <kanawha/kmalloc.h>
#include <kanawha/stree.h>
#include <kanawha/assert.h>
#include <kanawha/stddef.h>

int
environment_create(
        struct process *process)
{
    int res;

    struct environment *environ = kmalloc(sizeof(struct environment));
    if(environ == NULL) {
        return -ENOMEM;
    }
    memset(environ, 0, sizeof(struct environment));

    spinlock_init(&environ->lock);
    stree_init(&environ->env_table);
    ilist_init(&environ->process_list);

    res = environment_attach(environ, process);
    if(res) {
        kfree(environ);
        return res;
    }

    return 0;
}

int
environment_clone(
        struct environment *environ,
        struct process *process)
{
    int res;

    res = environment_create(process);
    if(res) {
        goto err0;
    }

    spin_lock(&environ->lock);

    struct stree_node *node;
    for(node = stree_get_first(&environ->env_table);
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
                &process->environ->env_table,
                &child_var->node);
        if(res) {
            kfree(child_var);
            kfree(key_dup);
            kfree(value_dup);
            goto err2;
        }
    }

    spin_unlock(&environ->lock);
    return 0;

err2:
    // Free any child variables we created
    environment_clear_all(process->environ);
err1:
    spin_unlock(&environ->lock);
err0:
    return res;
}

int
environment_attach(
        struct environment *environ,
        struct process *process)
{
    spin_lock(&environ->lock);

    ilist_push_tail(&environ->process_list, &process->environ_node);
    process->environ = environ;

    spin_unlock(&environ->lock);
    return 0;
}

int
environment_deattach(
        struct environment *environ,
        struct process *process)
{
    spin_lock(&environ->lock);

    ilist_remove(&environ->process_list, &process->environ_node);
    process->environ = NULL;

    if(ilist_empty(&environ->process_list)) {
        // We need to free the environment

        struct stree_node *node;
        do {
            node = stree_get_first(&environ->env_table);
            if(node == NULL) {
                break;
            }
            struct stree_node *rem =
                stree_remove(&environ->env_table, node->key);
            DEBUG_ASSERT(rem == node);

            struct envvar *var =
                container_of(node, struct envvar, node);

            kfree((void*)node->key);
            kfree((void*)var->value);
            kfree((void*)var);

        } while(1);

        // No one should be able to access the lock now,
        // so there's no point unlocking it before freeing

        kfree(environ);

    } else {
        // Only release the lock if there were other processes
        // still using the environment
        spin_unlock(&environ->lock);
    }

    return 0;
}

int
environment_clear_all(
        struct environment *environ)
{
    struct stree_node *node;

    spin_lock(&environ->lock);

    node = stree_get_first(&environ->env_table);
    while(node) {
        struct envvar *var =
            container_of(node, struct envvar, node);

        struct stree_node *rem =
            stree_remove(&environ->env_table, var->node.key);
        DEBUG_ASSERT(rem == node);

        kfree((void*)var->node.key);
        kfree((void*)var->value);
        kfree(var);

        node = stree_get_first(&environ->env_table);
    }

    spin_unlock(&environ->lock);
    return 0;
}

int
environment_clear_var(
        struct environment *environ,
        const char *var_name)
{
    spin_lock(&environ->lock);

    dprintk("Getting Node\n");
    struct stree_node *node =
        stree_get(&environ->env_table, var_name);

    if(node != NULL) {
        struct envvar *var =
            container_of(node, struct envvar, node);

        dprintk("Removing Node\n");
        struct stree_node *rem = stree_remove(
                &environ->env_table, var_name);
        DEBUG_ASSERT(rem == node);
       
        dprintk("Freeing key\n");
        kfree((void*)var->node.key);
        dprintk("Freeing value\n");
        kfree((void*)var->value);
        dprintk("Freeing var\n");
        kfree((void*)var);
    } else {
       spin_unlock(&environ->lock);
       return -ENXIO;
    }

    spin_unlock(&environ->lock);
    return 0;
}

int
environment_set(
        struct environment *environ,
        const char *var_name,
        const char *value)
{
    int res;

    spin_lock(&environ->lock);

    struct stree_node *node =
        stree_get(&environ->env_table, var_name);

    if(node == NULL)
    {
        struct envvar *var = kmalloc(sizeof(struct envvar));
        if(var == NULL) {
            spin_unlock(&environ->lock);
            return -ENOMEM;
        }
        memset(var, 0, sizeof(struct envvar));

        char *key_dup = kstrdup(var_name);
        if(key_dup == NULL) {
            kfree(var);
            spin_unlock(&environ->lock);
            return -ENOMEM;
        }
        char *value_dup = kstrdup(value);
        if(value_dup == NULL) {
            kfree(key_dup);
            kfree(var);
            spin_unlock(&environ->lock);
            return -ENOMEM;
        }

        var->value = value_dup;
        var->node.key = key_dup;

        res = stree_insert(
                &environ->env_table,
                &var->node);
        if(res) {
            kfree(value_dup);
            kfree(key_dup);
            kfree(var);
            spin_unlock(&environ->lock);
            return res;
        }

    } else {
        struct envvar *var =
            container_of(node, struct envvar, node);

        char *value_dup = kstrdup(value);
        if(value_dup == NULL) {
            spin_unlock(&environ->lock);
            return -ENOMEM;
        }

        kfree(var->value);
        var->value = value_dup;
    }

    spin_unlock(&environ->lock);
    return 0;
}

const char *
environment_get_var(
        struct environment *environ,
        const char *var_name)
{
    spin_lock(&environ->lock);

    struct stree_node *node =
        stree_get(
                &environ->env_table,
                var_name);

    if(node == NULL) {
        spin_unlock(&environ->lock);
        return NULL;
    }

    struct envvar *var =
        container_of(node, struct envvar, node);

    // NOTE: We don't unlock the environment on purpose here
    return var->value;
}

int
environment_put_var(
        struct environment *environ)
{
    // Assert we would fail if we tried locking the environment
    DEBUG_ASSERT(spin_try_lock(&environ->lock));

    spin_unlock(&environ->lock);
    return 0;
}

