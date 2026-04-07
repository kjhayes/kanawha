#ifndef __ELK_LIBC_INTERNAL__RINGBUF_H__
#define __ELK_LIBC_INTERNAL__RINGBUF_H__

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <kanawha/sys-wrappers.h>

struct __elk_libc_ringbuffer {
    char *buffer;
    size_t buflen;
    size_t head;
    size_t tail;
    size_t scale;
};

static inline int
__elk_libc_ringbuffer_init(
        struct __elk_libc_ringbuffer *buf,
        size_t scale)
{
    buf->buffer = NULL;
    buf->buflen = 0;
    buf->head = 0;
    buf->tail = 0;
    buf->scale = scale;
    return 0;
}

static inline int
__elk_libc_ringbuffer_deinit(
        struct __elk_libc_ringbuffer *buf) 
{
    if(buf->buffer) {
        free(buf->buffer);
    }

    // Being pedantic
    buf->buflen = 0;
    buf->head = 0;
    buf->tail = 0;

    return 0;
}

static inline int
__elk_libc_ringbuffer_full(
        struct __elk_libc_ringbuffer *buf)
{
    return ((buf->head+1)%buf->buflen) == buf->tail;
}

static inline int
__elk_libc_ringbuffer_empty(
        struct __elk_libc_ringbuffer *buf)
{
    return buf->head == buf->tail;
}

static inline size_t
__elk_libc_ringbuffer_enqueued(
        struct __elk_libc_ringbuffer *buf)
{
    if(buf->head == buf->tail) {
        buf->head = 0;
        buf->tail = 0;
        return 0;
    } else if(buf->tail < buf->head) {
        return buf->head - buf->tail;
    } else {
        size_t amt_end = buf->buflen - buf->tail;
        size_t amt_start = buf->head;
        return amt_end + amt_start;
    }
}

static inline int
__elk_libc_ringbuffer_grow(
        struct __elk_libc_ringbuffer *buf)
{
    size_t new_len;
    if(buf->buflen <= 1) {
        new_len = buf->scale+1;
    } else {
        new_len = ((buf->buflen-1) * 2)+1;
    }

    char *new_buf = malloc(new_len);
    if(new_buf == NULL) {
        return -ENOMEM;
    }

    size_t amt_buffered = 0;
    if(buf->tail == buf->head) {
        // Do nothing
    } else if(buf->tail < buf->head) {
        amt_buffered = buf->head - buf->tail;
        memcpy(new_buf, buf->buffer + buf->tail, amt_buffered);
    } else {
        size_t amt_end = buf->buflen - buf->tail;
        size_t amt_start = buf->head;
        memcpy(new_buf, buf->buffer + buf->tail, amt_end);
        memcpy(new_buf+amt_end, buf->buffer, amt_start);
        amt_buffered = amt_end + amt_start;
    }

    char *old = buf->buffer;
    buf->buffer = new_buf;
    buf->buflen = new_len;
    buf->tail = 0;
    buf->head = amt_buffered;
    if(old != NULL) {
        free(old);
    }

    return 0;
}

static inline int
__elk_libc_read_into_ringbuffer(
        int fd,
        struct __elk_libc_ringbuffer *buf,
        size_t maximum_read)
{
    int res;

    if(maximum_read == 0) {
        return -EINVAL;
    }

    if(__elk_libc_ringbuffer_full(buf)) {
        res = __elk_libc_ringbuffer_grow(buf);
        if(res) {
            return res;
        }
    }

    size_t room = 0;
    if(buf->tail <= buf->head) {
        room = (buf->buflen - buf->head) - (buf->tail == 0);
    } else {
        room = (buf->tail - buf->head) - 1;
    }

    if(room > maximum_read) {
        room = maximum_read;
    }

    ssize_t amt_read = kanawha_sys_read(
            fd,
            buf->buffer + buf->head,
            room);
    if(amt_read < 0) {
        return amt_read;
    }

    buf->head += amt_read;

    if(buf->head >= buf->buflen) {
        buf->head = 0;
    }
  
    return amt_read;
}

static inline ssize_t
__elk_libc_write_from_ringbuffer(
        int fd,
        struct __elk_libc_ringbuffer *buf)
{
    int res;

    if(__elk_libc_ringbuffer_empty(buf)) {
        return -EINVAL;
    }

    size_t room = 0;
    if(buf->tail < buf->head) {
        room = buf->head - buf->tail;
    } else {
        room = buf->buflen - buf->tail;
    }

    ssize_t amt_written = kanawha_sys_write(
            fd,
            buf->buffer + buf->tail,
            room);
    if(amt_written < 0) {
        return amt_written;
    }

    buf->tail += amt_written;

    if(buf->tail >= buf->buflen) {
        buf->tail = 0;
    }

    return amt_written;
}

static inline int
__elk_libc_ringbuffer_drop_data(
        struct __elk_libc_ringbuffer *buf)
{
    buf->head = 0;
    buf->tail = 0;
    buf->buflen = 0;
    if(buf->buffer) {
        free(buf->buffer);
        buf->buffer = NULL;
    }
}

#endif
