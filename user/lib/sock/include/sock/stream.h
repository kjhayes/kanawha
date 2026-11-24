#ifndef __SOCK__STREAM_H__
#define __SOCK__STREAM_H__

#include <stdlib.h>

struct sock_conn;
struct sock_stream;

int
sock_configure_stream(
        struct sock_conn *conn,
        unsigned long index,
        unsigned long buflen);

struct sock_stream *
sock_open_stream(
        struct sock_conn *conn,
        unsigned long index);
int
sock_close_stream(
        struct sock_stream *stream);

int
sock_stream_write(
        struct sock_stream *stream,
        void *buffer,
        size_t buflen);
int
sock_stream_read(
        struct sock_stream *stream,
        void *buffer,
        size_t buflen);

#endif
