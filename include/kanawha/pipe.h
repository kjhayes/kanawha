#ifndef __KANAWHA__PIPE_H__
#define __KANAWHA__PIPE_H__

#include <kanawha/ptree.h>
#include <kanawha/waitqueue.h>
#include <kanawha/lock.h>

#include <kanawha/fs/node.h>

struct pipe
{
    // This can probably be a thread_lock but we'll be safe for now
    irq_lock_t lock;

    size_t head;
    size_t tail;
    size_t buflen;
    void *buffer;

    struct waitqueue read_queue;
    struct waitqueue write_queue;
};

struct fs_node *
pipe_fs_get_anon_pipe(void);

#endif
