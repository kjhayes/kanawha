
#include <kanawha/pipe/ringbuf.h>
#include <kanawha/kmalloc.h>
#include <kanawha/assert.h>
#include <kanawha/errno.h>

#define PIPE_FS_PIPE_BUFLEN (0x100)

int
pipe_ringbuf_init(
        struct pipe_ringbuf *buf)
{
    buf->head = 0;
    buf->tail = 0;
    buf->data = kmalloc(PIPE_FS_PIPE_BUFLEN, KM_KERNEL);
    if(buf->data == NULL)
    {
        return -ENOMEM;
    }
    return 0;
}

int
pipe_ringbuf_deinit(
        struct pipe_ringbuf *buffer)
{
    DEBUG_ASSERT(KERNEL_ADDR(buffer));
    DEBUG_ASSERT(KERNEL_ADDR(buffer->data));
    kfree(buffer->data);
    return 0;
}

int
pipe_ringbuf_empty(
        struct pipe_ringbuf *buf)
{
    DEBUG_ASSERT(buf->head < PIPE_FS_PIPE_BUFLEN);
    DEBUG_ASSERT(buf->tail < PIPE_FS_PIPE_BUFLEN);
    return buf->head == buf->tail;
}

int
pipe_ringbuf_full(
        struct pipe_ringbuf *buf)
{
    DEBUG_ASSERT(buf->head < PIPE_FS_PIPE_BUFLEN);
    DEBUG_ASSERT(buf->tail < PIPE_FS_PIPE_BUFLEN);
    return ((buf->head + 1) % PIPE_FS_PIPE_BUFLEN) == buf->tail;
}

ssize_t
pipe_ringbuf_read(
        struct pipe_ringbuf *buf,
        void *data,
        size_t datalen)
{
    ssize_t read = 0;

    while(datalen > 0 && !pipe_ringbuf_empty(buf))
    {
        DEBUG_ASSERT(KERNEL_ADDR(buf));
        DEBUG_ASSERT(buf->head < PIPE_FS_PIPE_BUFLEN);
        DEBUG_ASSERT(buf->tail < PIPE_FS_PIPE_BUFLEN);
        DEBUG_ASSERT(KERNEL_ADDR(buf->data));

        size_t end = buf->tail > buf->head ? PIPE_FS_PIPE_BUFLEN : buf->head;
        size_t room = end - buf->tail;
        size_t amt = room < datalen ? room : datalen;

        memcpy(data, buf->data + buf->tail, amt);

        buf->tail = (buf->tail + amt) % PIPE_FS_PIPE_BUFLEN;
        read += amt;
        datalen -= amt;
        data += amt;
    }
    return read;
}

ssize_t
pipe_ringbuf_write(
        struct pipe_ringbuf *buf,
        void *data,
        size_t datalen)
{
    ssize_t written = 0;

    while(datalen > 0 && !pipe_ringbuf_full(buf))
    {
        DEBUG_ASSERT(KERNEL_ADDR(buf));
        DEBUG_ASSERT(buf->head < PIPE_FS_PIPE_BUFLEN);
        DEBUG_ASSERT(buf->tail < PIPE_FS_PIPE_BUFLEN);
        DEBUG_ASSERT(KERNEL_ADDR(buf->data));

        size_t end = buf->head >= buf->tail ? PIPE_FS_PIPE_BUFLEN : buf->tail;
        size_t room = end - buf->head;
        size_t amt = room < datalen ? room : datalen;

        memcpy(buf->data + buf->head, data, amt);
        buf->head = (buf->head + amt) % PIPE_FS_PIPE_BUFLEN;

        written += amt;
        datalen -= amt;
        data += amt;
    }

    return written;
}
