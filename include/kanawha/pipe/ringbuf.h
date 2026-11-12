#ifndef __KANAWHA__PIPE_RINGBUF_H__
#define __KANAWHA__PIPE_RINGBUF_H__

#include <kanawha/types.h>

struct pipe_ringbuf
{
    size_t head;
    size_t tail;
    void *data;
};

int
pipe_ringbuf_init(
        struct pipe_ringbuf *buf);
int
pipe_ringbuf_deinit(
        struct pipe_ringbuf *buf);

int
pipe_ringbuf_empty(
        struct pipe_ringbuf *buf);
int
pipe_ringbuf_full(
        struct pipe_ringbuf *buf);

ssize_t
pipe_ringbuf_read(
        struct pipe_ringbuf *buf,
        void *data,
        size_t datalen);
ssize_t
pipe_ringbuf_write(
        struct pipe_ringbuf *buf,
        void *data,
        size_t datalen);

#endif
