#ifndef __KANAWHA__PCACHE_H__
#define __KANAWHA__PCACHE_H__

#include <kanawha/ops.h>
#include <kanawha/lock.h>
#include <kanawha/atomic.h>

// struct fields should only be accessed from
// within the "pcache" subsystem, not consumers
struct pcache
{
    struct pcache_ops *ops;

    irq_lock_t node_tree_lock;
    struct ptree node_tree;
};
struct pcache_node
{
    struct pcache *pcache;
    atomic_t refcount;
    struct ptree_node cache_node;
};

#define PCACHE_LOAD_NODE_SIG(RET,ARG,...)\
RET(int)\
ARG(size_t, index)\
ARG(struct pcache_node **, out)

#define PCACHE_UNLOAD_NODE_SIG(RET,ARG,...)\
RET(int)\
ARG(size_t, index)\
ARG(struct pcache_node *, node)

#define PCACHE_FLUSH_NODE_SIG(RET,ARG,...)\
RET(int)\
ARG(size_t, index)\
ARG(struct pcache_node *, node)

#define PCACHE_OPS_LIST(OP,...)\
OP(load_node, PCACHE_LOAD_NODE_SIG, ##__VA_ARGS__)\
OP(unload_node, PCACHE_UNLOAD_NODE_SIG, ##__VA_ARGS__)\
OP(flush_node, PCACHE_FLUSH_NODE_SIG, ##__VA_ARGS__)\

struct pcache_ops {
DECLARE_OP_LIST_PTRS(PCACHE_OPS_LIST, struct pcache *)
};

int
pcache_init(
        struct pcache *,
        struct pcache_ops *);
int
pcache_deinit(
        struct pcache *);

DEFINE_OP_LIST_WRAPPERS(
        PCACHE_OPS_LIST,
        static inline,
        /* No Namespace */,
        pcache,
        OPS_STRUCT_PTR_ACCESSOR,
        SELF_ACCESSOR);

struct pcache *
pcache_node_get_cache(
        struct pcache_node *node);

void
pcache_node_get(
        struct pcache_node *node);
void
pcache_node_put(
        struct pcache_node *node);

int
pcache_lookup_node(
        struct pcache *cache,
        size_t index,
        struct pcache_node **out);

size_t
pcache_node_get_index(
        struct pcache_node *node);

#endif
