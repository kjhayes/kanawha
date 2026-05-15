#ifndef __KANAWHA__REGISTRY_H__
#define __KANAWHA__REGISTRY_H__

#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/list.h>
#include <kanawha/lock.h>
#include <kanawha/ops.h>
#include <kanawha/printk.h>
#include <kanawha/stddef.h>
#include <kanawha/stree.h>

/*
 * Declarations
 */

struct registry_node
{
    struct stree_node snode;

    ilist_node_t owner_node;
    void *owner;

    void *owner_priv_data;
};

#define __DECLARE_REGISTRY_PUBLIC_DATA(SNAME)                                  \
    DECLARE_GLOBAL_IRQ_LOCK(SNAME##_registry_lock)

#define __DECLARE_REGISTRY_REGISTER_FUNC(SNAME)                                \
    int register_##SNAME(struct SNAME *member, const char *name);

#define __DECLARE_REGISTRY_UNREGISTER_FUNC(SNAME)                              \
    int unregister_##SNAME(struct SNAME *member);

#define __DECLARE_REGISTRY_GET_NAME_FUNC(SNAME)                                \
    const char *SNAME##_get_name(struct SNAME *member);

// Hooking Functions
#define __DECLARE_REGISTRY_HOOK_STRUCT(SNAME)                                  \
    struct SNAME##_registry_hook                                               \
    {                                                                          \
        void (*on_register)(struct SNAME * member);                            \
        void (*on_unregister)(struct SNAME * member);                          \
        ilist_node_t list_node;                                                \
    };
#define __DECLARE_REGISTRY_HOOK_FUNC(SNAME)                                    \
    struct SNAME##_registry_hook *hook_##SNAME##_registry(                     \
        void (*on_register)(struct SNAME * member),                            \
        void (*on_unregister)(struct SNAME * member));
#define __DECLARE_REGISTRY_UNHOOK_FUNC(SNAME)                                  \
    int unhook_##SNAME##_registry(struct SNAME##_registry_hook *hook);

#define __DECLARE_REGISTRY_FOR_EACH_FUNC(SNAME)                                \
    int for_each_##SNAME(void (*callback)(struct SNAME *, void *), void *state);

#define __DECLARE_REGISTRY_DUMP_FUNC(SNAME)                                    \
    int dump_##SNAME##_registry(printk_f *printer);

// Ownership/Claim Functions

#define __DECLARE_REGISTRY_OWNER_STRUCT(SNAME)                                 \
    struct SNAME##_owner                                                       \
    {                                                                          \
        int (*probe)(struct SNAME * sname);                                    \
        int (*receive)(struct SNAME * sname);                                  \
        int (*revoke)(struct SNAME * sname);                                   \
                                                                               \
        ilist_node_t list_node;                                                \
        ilist_t owned_list;                                                    \
    };

#define __DECLARE_REGISTRY_OWNER_REGISTER_FUNC(SNAME)                          \
    int register_##SNAME##_owner(struct SNAME##_owner *owner);

#define __DECLARE_REGISTRY_OWNER_UNREGISTER_FUNC(SNAME)                        \
    int unregister_##SNAME##_owner(struct SNAME##_owner *owner);

#define DECLARE_REGISTRY(SNAME)                                                \
    __DECLARE_REGISTRY_PUBLIC_DATA(SNAME);                                     \
    __DECLARE_REGISTRY_REGISTER_FUNC(SNAME);                                   \
    __DECLARE_REGISTRY_UNREGISTER_FUNC(SNAME);                                 \
    __DECLARE_REGISTRY_GET_NAME_FUNC(SNAME);                                   \
    __DECLARE_REGISTRY_HOOK_STRUCT(SNAME);                                     \
    __DECLARE_REGISTRY_HOOK_FUNC(SNAME);                                       \
    __DECLARE_REGISTRY_UNHOOK_FUNC(SNAME);                                     \
    __DECLARE_REGISTRY_DUMP_FUNC(SNAME);                                       \
    __DECLARE_REGISTRY_FOR_EACH_FUNC(SNAME);                                   \
    __DECLARE_REGISTRY_OWNER_STRUCT(SNAME);                                    \
    __DECLARE_REGISTRY_OWNER_REGISTER_FUNC(SNAME);                             \
    __DECLARE_REGISTRY_OWNER_UNREGISTER_FUNC(SNAME);

/*
 * Definitions
 */

#define __DEFINE_REGISTRY_PUBLIC_DATA(SNAME)                                   \
    DEFINE_GLOBAL_IRQ_LOCK(SNAME##_registry_lock);

#define __DEFINE_REGISTRY_PRIVATE_DATA(SNAME)                                  \
    static DECLARE_STREE(SNAME##_registry_tree);                               \
    static DECLARE_ILIST(SNAME##_registry_hook_list);                          \
    static DECLARE_ILIST(SNAME##_registry_owner_list);                         \
    static DECLARE_ILIST(SNAME##_registry_unowned_list);

#define __DEFINE_REGISTRY_REGISTER_FUNC(SNAME, REG_NODE_FIELD, INIT_FUNCTION)  \
    int register_##SNAME(struct SNAME *member, const char *name)               \
    {                                                                          \
        int res;                                                               \
                                                                               \
        struct registry_node *reg_node = &member->REG_NODE_FIELD;              \
        memset(reg_node, 0, sizeof(*reg_node));                                \
        reg_node->snode.key = name;                                            \
                                                                               \
        res = INIT_FUNCTION(member);                                           \
        if(res)                                                                \
        {                                                                      \
            return res;                                                        \
        }                                                                      \
                                                                               \
        SNAME##_registry_lock_acquire();                                       \
                                                                               \
        struct stree_node *existing = stree_get(&SNAME##_registry_tree, name); \
        if(existing != NULL)                                                   \
        {                                                                      \
            SNAME##_registry_lock_release();                                   \
            return -EEXIST;                                                    \
        }                                                                      \
                                                                               \
        stree_insert(&SNAME##_registry_tree, &member->REG_NODE_FIELD.snode);   \
                                                                               \
        ilist_node_t *node;                                                    \
        ilist_for_each(node, &SNAME##_registry_hook_list)                      \
        {                                                                      \
            struct SNAME##_registry_hook *hook =                               \
                container_of(node, struct SNAME##_registry_hook, list_node);   \
            (*hook->on_register)(member);                                      \
        }                                                                      \
                                                                               \
        reg_node->owner = NULL;                                                \
        ilist_node_t *iter;                                                    \
        ilist_for_each(iter, &(SNAME##_registry_owner_list))                   \
        {                                                                      \
            int res;                                                           \
            struct SNAME##_owner *owner =                                      \
                container_of(iter, struct SNAME##_owner, list_node);           \
                                                                               \
            res = (*owner->probe)(member);                                     \
            if(res)                                                            \
            {                                                                  \
                continue;                                                      \
            }                                                                  \
                                                                               \
            res = (*owner->receive)(member);                                   \
            if(res)                                                            \
            {                                                                  \
                continue;                                                      \
            }                                                                  \
                                                                               \
            ilist_push_tail(&owner->owned_list, &reg_node->owner_node);        \
            reg_node->owner = (void *)owner;                                   \
            break;                                                             \
        }                                                                      \
                                                                               \
        if(reg_node->owner == NULL)                                            \
        {                                                                      \
            ilist_push_tail(&(SNAME##_registry_unowned_list),                  \
                            &reg_node->owner_node);                            \
        }                                                                      \
                                                                               \
        SNAME##_registry_lock_release();                                       \
        return 0;                                                              \
    }

#define __DEFINE_REGISTRY_UNREGISTER_FUNC(SNAME,                               \
                                          REG_NODE_FIELD,                      \
                                          DEINIT_FUNCTION)                     \
    int unregister_##SNAME(struct SNAME *member)                               \
    {                                                                          \
        int res;                                                               \
        struct registry_node *reg_node = &member->REG_NODE_FIELD;              \
        \
        DEBUG_ASSERT(KERNEL_ADDR(member)); \
                                                                               \
        SNAME##_registry_lock_acquire();                                       \
                                                                               \
        if(reg_node->owner != NULL)                                            \
        {                                                                      \
            struct SNAME##_owner *owner = reg_node->owner;                     \
            if(owner->revoke) { \
                res = (*owner->revoke)(member);                                    \
                if(res)                                                            \
                {                                                                  \
                    SNAME##_registry_lock_release();                               \
                    return res;                                                    \
                }                                                                  \
            } \
            ilist_remove(&owner->owned_list, &reg_node->owner_node);           \
        }                                                                      \
        else                                                                   \
        {                                                                      \
            ilist_remove(&(SNAME##_registry_unowned_list),                     \
                         &reg_node->owner_node);                               \
        }                                                                      \
                                                                               \
        ilist_node_t *node;                                                    \
        ilist_for_each(node, &SNAME##_registry_hook_list)                      \
        {                                                                      \
            struct SNAME##_registry_hook *hook =                               \
                container_of(node, struct SNAME##_registry_hook, list_node);   \
            (*hook->on_unregister)(member);                                    \
        }                                                                      \
                                                                               \
        struct stree_node *removed;                                            \
        removed = stree_remove(&(SNAME##_registry_tree), reg_node->snode.key); \
        DEBUG_ASSERT(removed == &reg_node->snode);                             \
                                                                               \
        SNAME##_registry_lock_release();                                       \
                                                                               \
        res = DEINIT_FUNCTION(member);                                         \
        if(res)                                                                \
        {                                                                      \
            return res;                                                        \
        }                                                                      \
                                                                               \
        return -EUNIMPL;                                                       \
    }

#define __DEFINE_REGISTRY_GET_NAME_FUNC(SNAME, REG_NODE_FIELD)                 \
    const char *SNAME##_get_name(struct SNAME *member)                         \
    {                                                                          \
        return member->REG_NODE_FIELD.snode.key;                               \
    }

#define __DEFINE_REGISTRY_HOOK_FUNC(SNAME, REG_NODE_FIELD)                     \
    struct SNAME##_registry_hook *hook_##SNAME##_registry(                     \
        void (*on_register)(struct SNAME * member),                            \
        void (*on_unregister)(struct SNAME * member))                          \
    {                                                                          \
        struct SNAME##_registry_hook *hook =                                   \
            kmalloc(sizeof(*hook), KM_KERNEL);                                 \
        if(hook == NULL)                                                       \
        {                                                                      \
            return NULL;                                                       \
        }                                                                      \
        hook->on_register = on_register;                                       \
        hook->on_unregister = on_register;                                     \
                                                                               \
        SNAME##_registry_lock_acquire();                                       \
                                                                               \
        ilist_push_tail(&SNAME##_registry_hook_list, &hook->list_node);        \
                                                                               \
        struct stree_node *node = stree_get_first(&SNAME##_registry_tree);     \
        for(; node != NULL; node = stree_get_next(node))                       \
        {                                                                      \
            struct SNAME *member =                                             \
                container_of(node, struct SNAME, REG_NODE_FIELD.snode);        \
                                                                               \
            (*on_register)(member);                                            \
        }                                                                      \
                                                                               \
        SNAME##_registry_lock_release();                                       \
                                                                               \
        return hook;                                                           \
    }

#define __DEFINE_REGISTRY_UNHOOK_FUNC(SNAME, REG_NODE_FIELD)                   \
    int unhook_##SNAME##_registry(struct SNAME##_registry_hook *hook)          \
    {                                                                          \
        return -EUNIMPL;                                                       \
    }

#define __DEFINE_REGISTRY_FOR_EACH_FUNC(SNAME, REG_NODE_FIELD)                 \
    int for_each_##SNAME(void (*callback)(struct SNAME *, void *),             \
                         void *state)                                          \
    {                                                                          \
        SNAME##_registry_lock_acquire();                                       \
                                                                               \
        struct stree_node *iter = stree_get_first(&SNAME##_registry_tree);     \
        while(iter)                                                            \
        {                                                                      \
            (*callback)(                                                       \
                container_of(iter, struct SNAME, REG_NODE_FIELD.snode),        \
                state);                                                        \
            iter = stree_get_next(iter);                                       \
        }                                                                      \
                                                                               \
        SNAME##_registry_lock_release();                                       \
        return 0;                                                              \
    }

#define __DEFINE_REGISTRY_DUMP_FUNC(SNAME)                                     \
    int dump_##SNAME##_registry(printk_f *printer)                             \
    {                                                                          \
        SNAME##_registry_lock_acquire();                                       \
                                                                               \
        (*printer)(#SNAME "_registry {\n");                                    \
                                                                               \
        struct stree_node *iter = stree_get_first(&SNAME##_registry_tree);     \
        while(iter)                                                            \
        {                                                                      \
            (*printer)("\t%s\n", iter->key);                                   \
            iter = stree_get_next(iter);                                       \
        }                                                                      \
        (*printer)("}\n");                                                     \
                                                                               \
        SNAME##_registry_lock_release();                                       \
        return 0;                                                              \
    }

#define __DEFINE_REGISTRY_OWNER_REGISTER_FUNC(SNAME, REG_NODE_FIELD)           \
    int register_##SNAME##_owner(struct SNAME##_owner *owner)                  \
    {                                                                          \
        int res;                                                               \
                                                                               \
        ilist_init(&owner->owned_list);                                        \
                                                                               \
        SNAME##_registry_lock_acquire();                                       \
        ilist_push_tail(&SNAME##_registry_owner_list, &owner->list_node);      \
                                                                               \
        ilist_node_t *iter;                                                    \
        int registered;                                                        \
        do                                                                     \
        {                                                                      \
            registered = 0;                                                    \
            ilist_for_each(iter, &(SNAME##_registry_unowned_list))             \
            {                                                                  \
                struct SNAME *member =                                         \
                    container_of(iter,                                         \
                                 struct SNAME,                                 \
                                 REG_NODE_FIELD.owner_node);                   \
                struct registry_node *reg_node = &member->REG_NODE_FIELD;      \
                                                                               \
                res = (*owner->probe)(member);                                 \
                if(res)                                                        \
                {                                                              \
                    continue;                                                  \
                }                                                              \
                res = (*owner->receive)(member);                               \
                if(res)                                                        \
                {                                                              \
                    continue;                                                  \
                }                                                              \
                                                                               \
                ilist_remove(&(SNAME##_registry_unowned_list), iter);          \
                ilist_push_tail(&owner->owned_list, iter);                     \
                reg_node->owner = (void *)owner;                               \
                registered = 1;                                                \
                break;                                                         \
            }                                                                  \
        } while(registered);                                                   \
                                                                               \
        SNAME##_registry_lock_release();                                       \
        return 0;                                                              \
    }

#define __DEFINE_REGISTRY_OWNER_UNREGISTER_FUNC(SNAME, REG_NODE_FIELD)         \
    int unregister_##SNAME##_owner(struct SNAME##_owner *owner)                \
    {                                                                          \
        int res;                                                               \
        SNAME##_registry_lock_acquire();                                       \
        ilist_remove(&SNAME##_registry_owner_list, &owner->list_node);         \
                                                                               \
        while(1)                                                               \
        {                                                                      \
            ilist_node_t *removed = ilist_pop_tail(&owner->owned_list);        \
            if(removed == NULL)                                                \
            {                                                                  \
                break;                                                         \
            }                                                                  \
            struct SNAME *member = container_of(removed,                       \
                                                struct SNAME,                  \
                                                REG_NODE_FIELD.owner_node);    \
            struct registry_node *reg_node = &member->REG_NODE_FIELD;          \
                                                                               \
            DEBUG_ASSERT(reg_node->owner == owner);                            \
            reg_node->owner = NULL;                                            \
            ilist_push_tail(&(SNAME##_registry_unowned_list),                  \
                            &reg_node->owner_node);                            \
        }                                                                      \
                                                                               \
        SNAME##_registry_lock_release();                                       \
        return 0;                                                              \
    }

// INIT_FUNCTION   -> int init_function(struct SNAME *member);
//     Should return 0 on success, negative errno on failure
// DEINIT_FUNCTION -> int deinit_function(struct SNAME *member);
//     Should return 0 on success, negative errno on failure

#define REGISTRY_NO_INIT_FUNCTION(ptr) (0) /* Always Succeed */
#define REGISTRY_NO_DEINIT_FUNCTION(ptr) (0)

#define DEFINE_REGISTRY(SNAME, REG_NODE_FIELD, INIT_FUNCTION, DEINIT_FUNCTION) \
    __DEFINE_REGISTRY_PUBLIC_DATA(SNAME);                                      \
    __DEFINE_REGISTRY_PRIVATE_DATA(SNAME);                                     \
    __DEFINE_REGISTRY_REGISTER_FUNC(SNAME, REG_NODE_FIELD, INIT_FUNCTION);     \
    __DEFINE_REGISTRY_UNREGISTER_FUNC(SNAME, REG_NODE_FIELD, DEINIT_FUNCTION); \
    __DEFINE_REGISTRY_GET_NAME_FUNC(SNAME, REG_NODE_FIELD);                    \
    __DEFINE_REGISTRY_HOOK_FUNC(SNAME, REG_NODE_FIELD);                        \
    __DEFINE_REGISTRY_UNHOOK_FUNC(SNAME, REG_NODE_FIELD);                      \
    __DEFINE_REGISTRY_DUMP_FUNC(SNAME);                                        \
    __DEFINE_REGISTRY_FOR_EACH_FUNC(SNAME, REG_NODE_FIELD);                    \
    __DEFINE_REGISTRY_OWNER_REGISTER_FUNC(SNAME, REG_NODE_FIELD);              \
    __DEFINE_REGISTRY_OWNER_UNREGISTER_FUNC(SNAME, REG_NODE_FIELD);

#define LOCAL_REGISTRY_HOOK(HOOK_NAME, SNAME, ON_REGISTER, ON_UNREGISTER)      \
    static struct SNAME##_registry_hook *HOOK_NAME = NULL;                     \
    static int __init_##HOOK_NAME(void)                                        \
    {                                                                          \
        HOOK_NAME = hook_##SNAME##_registry(ON_REGISTER, ON_UNREGISTER);       \
        if(HOOK_NAME == NULL)                                                  \
        {                                                                      \
            return -ENOMEM;                                                    \
        }                                                                      \
        return 0;                                                              \
    }                                                                          \
    declare_init(dynamic, __init_##HOOK_NAME);

#endif
