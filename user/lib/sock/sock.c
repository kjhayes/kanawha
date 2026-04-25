
#include <sock/sock.h>

#include <kanawha/sys-wrappers.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

struct sock_socket {
    int socket_fd;
};

int
sock_create_socket(const char *name)
{
    int res;
    int socket_fd;

    res = kanawha_sys_socket(0, 0, &socket_fd);
    if(res)
    {
        return res;
    }

    char SOCK_NUM_BUFFER[64];
    snprintf(SOCK_NUM_BUFFER, 64, "%d", socket_fd);
    SOCK_NUM_BUFFER[64 - 1] = '\0';
    setenv(name, SOCK_NUM_BUFFER, 1);

    return 0;
}

struct sock_socket *
sock_open_socket(const char *name)
{
    const char *socket_env = getenv(name);
    if(socket_env == NULL)
    {
        return NULL;
    }
    int socket_fd = strtoul(socket_env, NULL, 10);

    struct sock_socket *socket = malloc(sizeof(struct sock_socket));
    if(socket == NULL) {
        return NULL;
    }
    socket->socket_fd = socket_fd;
    return socket;
}

int
sock_close_socket(struct sock_socket *socket)
{
    free(socket);
    return 0;
}

int
sock_open_client_connection(
        struct sock_socket *socket,
        struct sock_connection *conn
        )
{
    int res;

    int conn_fd;
    res = kanawha_sys_connect(socket->socket_fd, &conn_fd, 0);
    if(res) {
        return res;
    }

    res = sock_connection_init(
            conn,
            conn_fd);
    if(res) {
        return res;
    }

    return 0;
}

int
sock_close_client_connection(
        struct sock_connection *conn)
{
    int fd = conn->conn_fd;
    sock_connection_deinit(conn);
    close(fd);
    return 0;
}

int
sock_open_server_connection(
        struct sock_socket *socket,
        struct sock_connection *conn
        )
{
    int res;
    int conn_fd;
retry:

    res = kanawha_sys_accept(socket->socket_fd, &conn_fd, 0);
    if(res) {
        if(res == -EINTR) {
            goto retry;
        }
        return res;
    }

    res = sock_connection_init(
            conn,
            conn_fd);
    if(res) {
        return res;
    }

    return 0;
}
int
sock_close_server_connection(
        struct sock_connection *conn)
{
    int fd = conn->conn_fd;
    sock_connection_deinit(conn);
    close(fd);
    return 0;
}

