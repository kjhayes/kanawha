
#include <kanawha/pipe.h>
#include <kanawha/stdint.h>
#include <kanawha/spinlock.h>
#include <kanawha/process.h>
#include <kanawha/usermode.h>
#include <kanawha/kmalloc.h>

// Creates a pipe with refcount=1
struct pipe *
create_pipe(size_t bufsize)
{
    struct pipe *pipe = kmalloc(sizeof(struct pipe));
    if(pipe == NULL) {
        return NULL;
    }
    pipe->buflen = bufsize;
    pipe->buffer = kmalloc(bufsize);
    if(pipe->buffer == NULL) {
        kfree(pipe);
        return NULL;
    }

    spinlock_init(&pipe->lock);
    pipe->refs = 1;

    return pipe;
}

// Increments the reference count of "pipe"
int
pipe_get(struct pipe *pipe)
{
    spin_lock(&pipe->lock);
    pipe->refs++;
    spin_unlock(&pipe->lock);
    return 0;
}

// Decrements the reference count of "pipe"
// (if the count reaches zero, it will destroy the pipe)
int
pipe_put(struct pipe *pipe)
{
    spin_lock(&pipe->lock);
    pipe->refs--;
    if(pipe->refs <= 0) {
        kfree(pipe->buffer);
        kfree(pipe);
    } else {
        spin_unlock(&pipe->lock);
    }
    return 0;
}

ssize_t
pipe_write(
        struct pipe *pipe,
        void *src,
        size_t len)
{
    if(len == 0) {
        return 0;
    }

    ssize_t written = 0;
    spin_lock(&pipe->lock);

    // TODO: Allow writes of more than a byte at a time
    if(((pipe->head+1)%pipe->buflen) != pipe->tail) {
        // The buffer still has room
        ((uint8_t*)pipe->buffer)[pipe->head] = *(uint8_t*)src;
        pipe->head = (pipe->head + 1) % pipe->buflen;
        written = 1;
    }

    spin_unlock(&pipe->lock);
    return written;
}

ssize_t
pipe_read(
        struct pipe *pipe,
        void *dst,
        size_t len)
{
    if(len == 0) {
        return 0;
    }

    ssize_t read = 0;
    spin_lock(&pipe->lock);

    // TODO: Allow reads of more than a byte per call
    if(pipe->head != pipe->tail) {
        // The buffer is non-empty
        *(uint8_t*)dst = ((uint8_t*)pipe->buffer)[pipe->tail];
        pipe->tail = (pipe->tail + 1) % pipe->buflen;
        read = 1;
    }

    spin_unlock(&pipe->lock);
    return read;
}

