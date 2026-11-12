#ifndef __KANAWHA__PIPE_H__
#define __KANAWHA__PIPE_H__

#include <kanawha/ringbuf.h>
#include <kanawha/fs/node.h>
#include <kanawha/waitqueue.h>

struct fs_node *
pipe_create_pipe_anonymous(void);

struct fs_node *
pipe_create_mux_anonymous(void);

struct pipe_fs_node
{
    struct fs_node *fs_node;
    struct ptree_node pnode;
    irq_lock_t lock;
    enum
    {
        PIPE_FS_NODE_MUX,
        PIPE_FS_NODE_BUFFER,
    } type;
};

struct pipe_fs_mux
{
    struct pipe_fs_node node;

    struct waitqueue pending_wq;
    struct waitqueue unpaired_wq;

    enum
    {
        PIPE_MUX_STATUS_NONE,
        PIPE_MUX_STATUS_WAITING_FOR_SERVER,
        PIPE_MUX_STATUS_WAITING_FOR_CLIENT,
        PIPE_MUX_STATUS_PAIRED,
    } status;

    int unpaired_result;
    size_t unpaired_inode;
};

static inline struct pipe_fs_mux *
pipe_fs_node_as_mux(
        struct pipe_fs_node *node)
{
    if(node == NULL) {
        return NULL;
    }
    if(node->type != PIPE_FS_NODE_MUX) {
        return NULL;
    }
    return container_of(node, struct pipe_fs_mux, node);
}
static inline struct pipe_fs_node *
pipe_fs_mux_as_node(
        struct pipe_fs_mux *node)
{
    return &node->node;
}

struct pipe_fs_buffer
{
    struct pipe_fs_node node;

    int num_readers;
    int num_writers;
    int num_clients;
    int num_servers;

    unsigned primary_inited : 1;
    struct waitqueue primary_write_wq;
    struct waitqueue primary_read_wq;
    struct ringbuf primary_ringbuf;

    unsigned secondary_inited : 1;
    struct waitqueue secondary_write_wq;
    struct waitqueue secondary_read_wq;
    struct ringbuf secondary_ringbuf;

    irq_lock_t page_tree_lock;
    struct ptree page_tree;
};

static inline struct pipe_fs_buffer *
pipe_fs_node_as_buffer(
        struct pipe_fs_node *node)
{
    if(node == NULL) {
        return NULL;
    }
    if(node->type != PIPE_FS_NODE_BUFFER) {
        return NULL;
    }
    return container_of(node, struct pipe_fs_buffer, node);
}
static inline struct pipe_fs_node *
pipe_fs_buffer_as_node(
        struct pipe_fs_buffer *node)
{
    return &node->node;
}

static inline void
pipe_lock_acquire(struct pipe_fs_node *pipe)
{
    irq_lock_acquire(&pipe->lock);
}
static inline void
pipe_lock_release(struct pipe_fs_node *pipe)
{
    irq_lock_release(&pipe->lock);
}

#endif
