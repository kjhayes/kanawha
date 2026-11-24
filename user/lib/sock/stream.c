
#include <sock/conn.h>
#include <sock/stream.h>
#include <stdlib.h>
#include <errno.h>

struct stream_ctrl {
    unsigned long head;
    unsigned long tail;
    unsigned char data[];
};

struct sock_stream {
    unsigned long datalen;
    struct sock_buffer *buffer;
    struct stream_ctrl *ctrl;
};

int
sock_configure_stream(
        struct sock_conn *conn,
        unsigned long index,
        unsigned long buflen)
{
    return sock_configure_buffer(
            conn,
            index,
            sizeof(struct stream_ctrl) + buflen);
}

struct sock_stream *
sock_open_stream(
        struct sock_conn *conn,
        unsigned long index)
{
    struct sock_stream *stream;
    stream = malloc(sizeof(*stream));
    if(stream == NULL) {
        return NULL;
    }

    struct sock_buffer *buffer;
    buffer = sock_open_buffer(conn, index);
    if(buffer == NULL)
    {
        free(stream);
        return NULL;
    }
    stream->buffer = buffer;
    stream->ctrl = sock_buffer_raw_view(buffer);
    unsigned long length = sock_buffer_raw_length(buffer);
    if(length <= sizeof(struct stream_ctrl)) {
        sock_close_buffer(buffer);
        free(stream);
        return NULL;
    }
    stream->datalen = length - sizeof(struct stream_ctrl);
    return stream;
}
int
sock_close_stream(
        struct sock_stream *stream)
{
    sock_close_buffer(stream->buffer);
    free(stream);
    return 0;
}

int
sock_stream_write(
        struct sock_stream *stream,
        void *buffer,
        size_t buflen)
{
    int res;
    while(buflen > 0) {
        unsigned long head = stream->ctrl->head;
        unsigned long tail = stream->ctrl->tail;
        if(head >= stream->datalen) {
            head = 0;
        }
        unsigned long room;
        if(head < tail) {
            room = tail - head - 1;
        } else {
            room = stream->datalen - head;
        }
        if(room == 0) {
            // We will spin waiting for the other
            // side of the stream to read
            continue;
        }

        if(room > buflen) {
            room = buflen;
        }

        res = sock_buffer_write(
                stream->buffer,
                sizeof(struct stream_ctrl) + head,
                buffer,
                room);
        if(res) {
            return res;
        }
        head += room;
        while(head >= stream->datalen) {
            head -= stream->datalen;
        }
        stream->ctrl->head = head;

        buffer += room;
        buflen -= room;
    }
    return 0;
}
int
sock_stream_read(
        struct sock_stream *stream,
        void *buffer,
        size_t buflen)
{
    int res;
    while(buflen > 0) {
        unsigned long head = stream->ctrl->head;
        unsigned long tail = stream->ctrl->tail;
        if(tail >= stream->datalen) {
            tail = 0;
        }
        unsigned long room;
        if(tail < head) {
            room = head - tail;
        } else {
            room = stream->datalen - tail;
        }
        if(room == 0) {
            // We will spin waiting for the other
            // side of the stream to read
            continue;
        }

        if(room > buflen) {
            room = buflen;
        }

        res = sock_buffer_read(
                stream->buffer,
                sizeof(struct stream_ctrl) + tail,
                buffer,
                room);
        if(res) {
            return res;
        }
        tail += room;
        while(tail >= stream->datalen) {
            tail -= stream->datalen;
        }
        stream->ctrl->tail = tail;

        buffer += room;
        buflen -= room;
    }
    return 0;
}

