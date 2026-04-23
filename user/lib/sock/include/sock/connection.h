#ifndef __KANAWHA__SOCK_CONNECTION_H__
#define __KANAWHA__SOCK_CONNECTION_H__

#include <semaphore.h>
#include <sock/msg.h>

struct sock_connection
{
    sem_t read_lock;
    sem_t write_lock;
    int(*on_recv)(
            struct sock_connection *self,
            struct sock_msg *msg);
    int conn_fd;

    enum {
        SOCK_CONNECTION_CONNECTED,
        SOCK_CONNECTION_DISCONNECTED,
    } status;
};

int
sock_connection_init(
        struct sock_connection *conn,
        int(*on_recv)(
            struct sock_connection *conn,
            struct sock_msg *msg),
        int conn_fd);

int
sock_connection_deinit(
        struct sock_connection *conn);

int
sock_connection_send_msg(
        struct sock_connection *conn,
        uint8_t type,
        uint8_t index,
        void *data,
        size_t datalen);

int
sock_connection_await_msg(
        struct sock_connection *conn);

#endif
