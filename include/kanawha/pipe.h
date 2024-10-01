#ifndef __KANAWHA__PIPE_H__
#define __KANAWHA__PIPE_H__

#include <kanawha/stdint.h>
#include <kanawha/spinlock.h>
#include <kanawha/process.h>
#include <kanawha/usermode.h>

struct pipe
{
    spinlock_t lock;
    int refs;

    size_t head;
    size_t tail;
    size_t buflen;
    void *buffer;
};

// Creates a pipe with refcount=1
struct pipe *
create_pipe(size_t bufsize);

// Increments the reference count of "pipe"
int
pipe_get(struct pipe *pipe);

// Decrements the reference count of "pipe"
// (if the count reaches zero, it will destroy the pipe)
int
pipe_put(struct pipe *pipe);

ssize_t
pipe_write(
        struct pipe *pipe,
        void *src,
        size_t len);

ssize_t
pipe_read(
        struct pipe *pipe,
        void *dst,
        size_t len);

#endif
