#ifndef __KANAWHA__DEV_H__
#define __KANAWHA__DEV_H__

#include <kanawha/ops.h>
#include <kanawha/lock.h>
#include <kanawha/stree.h>
#include <kanawha/list.h>
#include <kanawha/stddef.h>

/*
 * Declarations
 */

#define __DECLARE_DEV_STRUCT(DNAME)\
    struct DNAME ## _dev {\
        struct DNAME ## _driver *driver;\
        struct stree_node DNAME ## _dev_node;\
    };

#define __DECLARE_DRIVER_STRUCT(DNAME, OP_LIST)\
    struct DNAME ## _driver {\
        DECLARE_OP_LIST_PTRS(\
                OP_LIST,\
                struct DNAME ## _dev*)\
    };

#define __DECLARE_DRIVER_STRUCT_WRAPPERS(DNAME, OP_LIST)\
    DEFINE_OP_LIST_WRAPPERS(\
            OP_LIST,\
            static inline,\
            /* No Prefix */,\
            DNAME ## _dev,\
            DRIVER_STRUCT_PTR_ACCESSOR,\
            SELF_ACCESSOR);

#define __DECLARE_DEV_REGISTER_FUNC(DNAME)\
    int \
    register_ ## DNAME ## _dev(\
            struct DNAME ## _dev *dev,\
            const char *name,\
            struct DNAME ## _driver *driver);

#define __DECLARE_DEV_UNREGISTER_FUNC(DNAME)\
    int \
    unregister_ ## DNAME ## _dev(\
            struct DNAME ## _dev *dev);

#define __DECLARE_DEV_GET_NAME_FUNC(DNAME)\
    const char *\
    DNAME ## _dev_get_name(\
            struct DNAME ## _dev *dev);

// Hooking Functions
#define __DECLARE_DEV_HOOK_STRUCT(DNAME)\
    struct DNAME ## _dev_hook {\
        void(*on_register)(struct DNAME ## _dev *dev);\
        void(*on_unregister)(struct DNAME ## _dev *dev);\
        ilist_node_t list_node;\
    };
#define __DECLARE_DEV_HOOK_FUNC(DNAME)\
    struct DNAME ## _dev_hook * \
    hook_ ## DNAME ## _dev_registry(\
            void(*on_register)(struct DNAME ## _dev *dev),\
            void(*on_unregister)(struct DNAME ## _dev *dev)\
            );
#define __DECLARE_DEV_UNHOOK_FUNC(DNAME)\
    int \
    unhook_ ## DNAME ## _dev_registry(\
            struct DNAME ## _dev_hook *hook\
            );

#define DECLARE_DEV_TYPE(DNAME, OP_LIST)\
    __DECLARE_DEV_STRUCT(DNAME)\
    __DECLARE_DRIVER_STRUCT(DNAME, OP_LIST)\
    __DECLARE_DRIVER_STRUCT_WRAPPERS(DNAME, OP_LIST)\
    __DECLARE_DEV_REGISTER_FUNC(DNAME);\
    __DECLARE_DEV_UNREGISTER_FUNC(DNAME);\
    __DECLARE_DEV_GET_NAME_FUNC(DNAME);\
    __DECLARE_DEV_HOOK_STRUCT(DNAME)\
    __DECLARE_DEV_HOOK_FUNC(DNAME)\
    __DECLARE_DEV_UNHOOK_FUNC(DNAME)\

/*
 * Definitions
 */

#define __DEFINE_DEV_PRIVATE_DATA(DNAME)\
    static DECLARE_STREE(DNAME ## _dev_tree);\
    static DECLARE_ILIST(DNAME ## _dev_hook_list);\
    DEFINE_LOCAL_THREAD_LOCK(DNAME ## _dev_lock);\

#define __DEFINE_DEV_REGISTER_FUNC(DNAME)\
    int \
    register_ ## DNAME ## _dev(\
            struct DNAME ## _dev *dev,\
            const char *name,\
            struct DNAME ## _driver *driver)\
    {\
        int res;\
        \
        DNAME ## _dev_lock_acquire();\
        \
        struct stree_node *existing = stree_get(& DNAME ## _dev_tree, name);\
        if(existing != NULL) {\
            DNAME ## _dev_lock_release();\
            return -EEXIST;\
        }\
        dev->driver = driver;\
        dev-> DNAME ## _dev_node.key = name;\
        stree_insert(\
                & DNAME ## _dev_tree,\
                &dev-> DNAME ## _dev_node);\
        \
        ilist_node_t *node;\
        ilist_for_each(node, & DNAME ## _dev_hook_list) {\
            struct DNAME ## _dev_hook *hook =\
                container_of(node, struct DNAME ## _dev_hook, list_node);\
            (*hook->on_register)(dev);\
        }\
        \
        DNAME ## _dev_lock_release();\
        return 0;\
    }

#define __DEFINE_DEV_UNREGISTER_FUNC(DNAME)\
    int \
    unregister_ ## DNAME ## _dev(\
            struct DNAME ## _dev *dev)\
    {\
        return -EUNIMPL;\
    }

#define __DEFINE_DEV_GET_NAME_FUNC(DNAME)\
    const char *\
    DNAME ## _dev_get_name(\
            struct DNAME ## _dev *dev)\
    {\
        return dev-> DNAME ## _dev_node.key;\
    }

#define __DEFINE_DEV_HOOK_FUNC(DNAME)\
    struct DNAME ## _dev_hook *\
    hook_ ## DNAME ## _dev_registry(\
            void(*on_register)(struct DNAME ## _dev *dev),\
            void(*on_unregister)(struct DNAME ## _dev *dev)\
            )\
    {\
        struct DNAME ## _dev_hook *hook = kmalloc(sizeof(*hook));\
        if(hook == NULL) {\
            return NULL;\
        }\
        hook->on_register = on_register;\
        hook->on_unregister = on_register;\
        \
        DNAME ## _dev_lock_acquire();\
        \
        ilist_push_tail(& DNAME ## _dev_hook_list, &hook->list_node);\
        \
        struct stree_node *node = stree_get_first(& DNAME ## _dev_tree);\
        for(; node != NULL; node = stree_get_next(node)) {\
            struct DNAME ## _dev *dev =\
                container_of(node, struct DNAME ## _dev, DNAME ## _dev_node);\
            \
            (*on_register)(dev);\
        }\
        \
        DNAME ## _dev_lock_release();\
        \
        return hook;\
    }

#define __DEFINE_DEV_UNHOOK_FUNC(DNAME)\
    int \
    unhook_ ## DNAME ## _dev_registry(\
            struct DNAME ## _dev_hook *hook\
            )\
    {\
        return -EUNIMPL;\
    }

#define DEFINE_DEV_TYPE(DNAME)\
    __DEFINE_DEV_PRIVATE_DATA(DNAME);\
    __DEFINE_DEV_REGISTER_FUNC(DNAME);\
    __DEFINE_DEV_UNREGISTER_FUNC(DNAME);\
    __DEFINE_DEV_GET_NAME_FUNC(DNAME);\
    __DEFINE_DEV_HOOK_FUNC(DNAME);\
    __DEFINE_DEV_UNHOOK_FUNC(DNAME);\

#endif
