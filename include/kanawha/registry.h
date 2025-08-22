#ifndef __KANAWHA__REGISTRY_H__
#define __KANAWHA__REGISTRY_H__

#include <kanawha/ops.h>
#include <kanawha/lock.h>
#include <kanawha/printk.h>
#include <kanawha/stree.h>
#include <kanawha/list.h>
#include <kanawha/stddef.h>
#include <kanawha/kmalloc.h>

/*
 * Declarations
 */

struct registry_node {
    struct stree_node snode;
};

#define __DECLARE_REGISTRY_REGISTER_FUNC(SNAME)\
    int \
    register_ ## SNAME(\
            struct SNAME *member,\
            const char *name);

#define __DECLARE_REGISTRY_UNREGISTER_FUNC(SNAME)\
    int \
    unregister_ ## SNAME (\
            struct SNAME *member);

#define __DECLARE_REGISTRY_GET_NAME_FUNC(SNAME)\
    const char *\
    SNAME ## _get_name(\
            struct SNAME *member);

// Hooking Functions
#define __DECLARE_REGISTRY_HOOK_STRUCT(SNAME)\
    struct SNAME ## _registry_hook {\
        void(*on_register)(struct SNAME *member);\
        void(*on_unregister)(struct SNAME *member);\
        ilist_node_t list_node;\
    };
#define __DECLARE_REGISTRY_HOOK_FUNC(SNAME)\
    struct SNAME ## _registry_hook * \
    hook_ ## SNAME ## _registry(\
            void(*on_register)(struct SNAME *member),\
            void(*on_unregister)(struct SNAME *member)\
            );
#define __DECLARE_REGISTRY_UNHOOK_FUNC(SNAME)\
    int \
    unhook_ ## SNAME ## _registry(\
            struct SNAME ## _registry_hook *hook\
            );

#define __DECLARE_REGISTRY_DUMP_FUNC(SNAME)\
    int \
    dump_ ## SNAME ## _registry(\
            printk_f *printer);
 
#define DECLARE_REGISTRY(SNAME)\
    __DECLARE_REGISTRY_REGISTER_FUNC(SNAME);\
    __DECLARE_REGISTRY_UNREGISTER_FUNC(SNAME);\
    __DECLARE_REGISTRY_GET_NAME_FUNC(SNAME);\
    __DECLARE_REGISTRY_HOOK_STRUCT(SNAME);\
    __DECLARE_REGISTRY_HOOK_FUNC(SNAME);\
    __DECLARE_REGISTRY_UNHOOK_FUNC(SNAME);\
    __DECLARE_REGISTRY_DUMP_FUNC(SNAME);\

/*
 * Definitions
 */

#define __DEFINE_REGISTRY_PRIVATE_DATA(SNAME)\
    static DECLARE_STREE(SNAME ## _registry_tree);\
    static DECLARE_ILIST(SNAME ## _registry_hook_list);\
    DEFINE_LOCAL_THREAD_LOCK(SNAME ## _registry_lock);\

#define __DEFINE_REGISTRY_REGISTER_FUNC(SNAME, REG_NODE_FIELD, INIT_FUNCTION)\
    int \
    register_ ## SNAME (\
            struct SNAME *member,\
            const char *name)\
    {\
        int res;\
        \
	member->REG_NODE_FIELD.snode.key = name;\
	\
        res = INIT_FUNCTION(member);\
        if (res) {\
            return res;\
        }\
        \
        SNAME ## _registry_lock_acquire();\
        \
        struct stree_node *existing = stree_get(& SNAME ## _registry_tree, name);\
        if(existing != NULL) {\
            SNAME ## _registry_lock_release();\
            return -EEXIST;\
        }\
	\
        stree_insert(\
                & SNAME ## _registry_tree,\
                &member->REG_NODE_FIELD.snode);\
        \
        ilist_node_t *node;\
        ilist_for_each(node, & SNAME ## _registry_hook_list) {\
            struct SNAME ## _registry_hook *hook =\
                container_of(node, struct SNAME ## _registry_hook, list_node);\
            (*hook->on_register)(member);\
        }\
        \
        SNAME ## _registry_lock_release();\
        return 0;\
    }

#define __DEFINE_REGISTRY_UNREGISTER_FUNC(SNAME, REG_NODE_FIELD, DEINIT_FUNCTION)\
    int \
    unregister_ ## SNAME (\
            struct SNAME *member)\
    {\
        int res;\
        res = DEINIT_FUNCTION(member);\
        if (res) {\
            return res;\
        }\
        return -EUNIMPL;\
    }

#define __DEFINE_REGISTRY_GET_NAME_FUNC(SNAME, REG_NODE_FIELD)\
    const char *\
    SNAME ## _get_name(\
            struct SNAME *member)\
    {\
        return member->REG_NODE_FIELD.snode.key;\
    }

#define __DEFINE_REGISTRY_HOOK_FUNC(SNAME, REG_NODE_FIELD)\
    struct SNAME ## _registry_hook *\
    hook_ ## SNAME ## _registry(\
            void(*on_register)(struct SNAME *member),\
            void(*on_unregister)(struct SNAME *member)\
            )\
    {\
        struct SNAME ## _registry_hook *hook = kmalloc(sizeof(*hook), KM_KERNEL);\
        if(hook == NULL) {\
            return NULL;\
        }\
        hook->on_register = on_register;\
        hook->on_unregister = on_register;\
        \
        SNAME ## _registry_lock_acquire();\
        \
        ilist_push_tail(& SNAME ## _registry_hook_list, &hook->list_node);\
        \
        struct stree_node *node = stree_get_first(& SNAME ## _registry_tree);\
        for(; node != NULL; node = stree_get_next(node)) {\
            struct SNAME *member =\
                container_of(node, struct SNAME, REG_NODE_FIELD.snode);\
            \
            (*on_register)(member);\
        }\
        \
        SNAME ## _registry_lock_release();\
        \
        return hook;\
    }

#define __DEFINE_REGISTRY_UNHOOK_FUNC(SNAME, REG_NODE_FIELD)\
    int \
    unhook_ ## SNAME ## _registry(\
            struct SNAME ## _registry_hook *hook\
            )\
    {\
        return -EUNIMPL;\
    }

#define __DEFINE_REGISTRY_DUMP_FUNC(SNAME)\
    int \
    dump_ ## SNAME ## _registry(\
            printk_f *printer)\
    {\
        SNAME ## _registry_lock_acquire();\
        \
        (*printer)(#SNAME "_registry {\n");\
        \
        struct stree_node *iter = stree_get_first(&SNAME ## _registry_tree);\
        while(iter) {\
            (*printer)("\t%s\n", iter->key);\
            iter = stree_get_next(iter);\
        }\
        (*printer)("}\n");\
        \
        SNAME ## _registry_lock_release();\
        return 0;\
    }


// INIT_FUNCTION   -> int init_function(struct SNAME *member);
//     Should return 0 on success, negative errno on failure
// DEINIT_FUNCTION -> int deinit_function(struct SNAME *member);
//     Should return 0 on success, negative errno on failure

#define REGISTRY_NO_INIT_FUNCTION(ptr) (0) /* Always Succeed */
#define REGISTRY_NO_DEINIT_FUNCTION(ptr) (0)

#define DEFINE_REGISTRY(SNAME, REG_NODE_FIELD, INIT_FUNCTION, DEINIT_FUNCTION)\
    __DEFINE_REGISTRY_PRIVATE_DATA(SNAME);\
    __DEFINE_REGISTRY_REGISTER_FUNC(SNAME, REG_NODE_FIELD, INIT_FUNCTION);\
    __DEFINE_REGISTRY_UNREGISTER_FUNC(SNAME, REG_NODE_FIELD, DEINIT_FUNCTION);\
    __DEFINE_REGISTRY_GET_NAME_FUNC(SNAME, REG_NODE_FIELD);\
    __DEFINE_REGISTRY_HOOK_FUNC(SNAME, REG_NODE_FIELD);\
    __DEFINE_REGISTRY_UNHOOK_FUNC(SNAME, REG_NODE_FIELD);\
    __DEFINE_REGISTRY_DUMP_FUNC(SNAME);\

#endif
