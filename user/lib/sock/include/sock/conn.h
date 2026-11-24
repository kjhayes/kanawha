#ifndef __SOCK__CONN_H__
#define __SOCK__CONN_H__

#define SOCK_CONN_MAX_BUFFERS (16)
#define SOCK_BUFFER_ALIGN_ORDER (12)

struct sock_conn;

struct sock_conn *
sock_open_server_conn(
        int fd);
struct sock_conn *
sock_open_client_conn(
        int fd);
int
sock_close_conn(
        struct sock_conn *);

int
sock_configure_buffer(
        struct sock_conn *,
        unsigned long index,
        unsigned long length);

// Invoked by the server to notify the client
// the configuration is fixed now
//
// (the client waits until this call before
// it returns from "sock_open_client_conn")
int
sock_conn_finalize_config(
        struct sock_conn *conn);

struct sock_buffer;

struct sock_buffer *
sock_open_buffer(
        struct sock_conn *,
        unsigned long index);
int
sock_close_buffer(
        struct sock_buffer *);

int
sock_lock_buffer(
        struct sock_buffer *);
int
sock_unlock_buffer(
        struct sock_buffer *);

void *
sock_buffer_raw_view(
        struct sock_buffer *);
unsigned long
sock_buffer_raw_length(
        struct sock_buffer *);

int
sock_buffer_read(
        struct sock_buffer *,
        unsigned long offset,
        void *buffer,
        unsigned long len);
int
sock_buffer_write(
        struct sock_buffer *,
        unsigned long offset,
        void *buffer,
        unsigned long len);
int
sock_buffer_memset(
        struct sock_buffer *,
        unsigned long offset,
        int c,
        unsigned long len);

#endif
