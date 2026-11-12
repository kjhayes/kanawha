
#include <kanawha/ringbuf.h>
#include <kanawha/kmalloc.h>
#include <kanawha/assert.h>
#include <kanawha/errno.h>

int
ringbuf_init(
        struct ringbuf *buf,
        size_t buflen)
{
    buf->head = 0;
    buf->tail = 0;
    buf->buflen = buflen;
    buf->buffer = kmalloc(buf->buflen, KM_KERNEL);
    if(buf->buffer == NULL)
    {
        return -ENOMEM;
    }
    return 0;
}

int
ringbuf_deinit(
        struct ringbuf *buffer)
{
    DEBUG_ASSERT(KERNEL_ADDR(buffer));
    DEBUG_ASSERT(KERNEL_ADDR(buffer->buffer));
    kfree(buffer->buffer);
    return 0;
}

int
ringbuf_empty(
        struct ringbuf *buf)
{
    DEBUG_ASSERT(buf->head < buf->buflen);
    DEBUG_ASSERT(buf->tail < buf->buflen);
    return buf->head == buf->tail;
}

int
ringbuf_full(
        struct ringbuf *buf)
{
    DEBUG_ASSERT(buf->head < buf->buflen);
    DEBUG_ASSERT(buf->tail < buf->buflen);
    return ((buf->head + 1) % buf->buflen) == buf->tail;
}

ssize_t
ringbuf_read(
        struct ringbuf *buf,
        void *buffer,
        size_t bufferlen)
{
    ssize_t read = 0;

    while(bufferlen > 0 && !ringbuf_empty(buf))
    {
        DEBUG_ASSERT(KERNEL_ADDR(buf));
        DEBUG_ASSERT(buf->head < buf->buflen);
        DEBUG_ASSERT(buf->tail < buf->buflen);
        DEBUG_ASSERT(KERNEL_ADDR(buf->buffer));

        size_t end = buf->tail > buf->head ? buf->buflen : buf->head;
        size_t room = end - buf->tail;
        size_t amt = room < bufferlen ? room : bufferlen;

        memcpy(buffer, buf->buffer + buf->tail, amt);

        buf->tail = (buf->tail + amt) % buf->buflen;
        read += amt;
        bufferlen -= amt;
        buffer += amt;
    }
    return read;
}

ssize_t
ringbuf_write(
        struct ringbuf *buf,
        void *buffer,
        size_t bufferlen)
{
    ssize_t written = 0;

    while(bufferlen > 0 && !ringbuf_full(buf))
    {
        DEBUG_ASSERT(KERNEL_ADDR(buf));
        DEBUG_ASSERT(buf->head < buf->buflen);
        DEBUG_ASSERT(buf->tail < buf->buflen);
        DEBUG_ASSERT(KERNEL_ADDR(buf->buffer));

        size_t end = buf->head >= buf->tail ? buf->buflen : buf->tail;
        size_t room = end - buf->head;
        size_t amt = room < bufferlen ? room : bufferlen;

        memcpy(buf->buffer + buf->head, buffer, amt);
        buf->head = (buf->head + amt) % buf->buflen;

        written += amt;
        bufferlen -= amt;
        buffer += amt;
    }

    return written;
}
