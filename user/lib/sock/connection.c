
#include <sock/connection.h>
#include <sock/sock.h>
#include <sock/msg.h>

#include <kanawha/sys-wrappers.h>

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

int
sock_connection_init(
        struct sock_connection *conn,
        int(*on_recv)(
            struct sock_connection *conn,
            struct sock_msg *msg),
        int conn_fd)
{
    sem_init(&conn->read_lock, 1, 1);
    sem_init(&conn->write_lock, 1, 1);
    conn->on_recv = on_recv;
    conn->conn_fd = conn_fd;
    conn->status = SOCK_CONNECTION_CONNECTED;
}

int
sock_connection_deinit(
        struct sock_connection *conn)
{
    conn->status = SOCK_CONNECTION_DISCONNECTED;
    return 0;
}

static int
sock_connection_check_for_disconnect(
        struct sock_connection *conn)
{
    int res;
    unsigned long connected;
    res = kanawha_sys_fattr(conn->conn_fd, FILE_ATTR_CONNECTED, &connected);
    if(res)
    {
        return res;
    }
    if(!connected) {
        conn->status = SOCK_CONNECTION_DISCONNECTED;
    }
    return 0;
}

int
sock_connection_send_msg(
        struct sock_connection *conn,
        uint8_t type,
        uint8_t index,
        void *data,
        size_t datalen)
{
    int res;

    res = sock_connection_check_for_disconnect(conn);
    if(res) {
        return res;
    }

    if(conn->status != SOCK_CONNECTION_CONNECTED) {
        return -EINVAL;
    }

    sem_wait(&conn->write_lock);
    sem_post(&conn->write_lock);

    return 0;
}

int
sock_connection_await_msg(
        struct sock_connection *conn)
{
    int res;

    res = sock_connection_check_for_disconnect(conn);
    if(res) {
        return res;
    }

    if(conn->status != SOCK_CONNECTION_CONNECTED) {
        return -EINVAL;
    }

    struct sock_msg msg;
    sem_wait(&conn->read_lock);

    ssize_t amt = read(conn->conn_fd, &msg, sizeof(msg));
    if(amt != sizeof(msg)) {
        sem_post(&conn->read_lock);
        return -EFAULT;
    }

    size_t buflen = sizeof(struct sock_msg) + msg.length;
    void *buffer = malloc(buflen);
    if(buffer == NULL) {
        sem_post(&conn->read_lock);
        return -ENOMEM;
    }

    memcpy(buffer, &msg, sizeof(msg));
    amt = read(conn->conn_fd, buffer + sizeof(msg), msg.length);
    if(amt != msg.length) {
        return -EINVAL;
    }

    struct sock_msg *full = buffer;

    if(conn->on_recv != NULL) {
        res = (*conn->on_recv)(conn, full);
        if(res) {
            sem_post(&conn->read_lock);
            return res;
        }
    }

    sem_post(&conn->read_lock);
    return 0;
}

