#ifndef __KANAWHA__PIPE_H__
#define __KANAWHA__PIPE_H__

#include <kanawha/ptree.h>
#include <kanawha/waitqueue.h>
#include <kanawha/fs/node.h>

struct pipe
{
    spinlock_t lock;

    size_t head;
    size_t tail;
    size_t buflen;
    void *buffer;

    struct waitqueue read_queue;
    struct waitqueue write_queue;

    struct fs_node fs_node;
};

struct fs_node *
pipe_fs_get_anon_pipe(void);

#endif
