#ifndef __KANAWHA__RINGBUF_H__
#define __KANAWHA__RINGBUF_H__

#include <kanawha/types.h>

struct ringbuf {
    size_t head;
    size_t tail;
    size_t buflen;
    void *buffer;
};

int
ringbuf_init(
        struct ringbuf *buf,
        size_t buflen);
int
ringbuf_deinit(
        struct ringbuf *buffer);

int
ringbuf_empty(
        struct ringbuf *buf);
int
ringbuf_full(
        struct ringbuf *buf);

ssize_t
ringbuf_read(
        struct ringbuf *buf,
        void *data,
        size_t datalen);
ssize_t
ringbuf_write(
        struct ringbuf *buf,
        void *data,
        size_t datalen);

#endif
