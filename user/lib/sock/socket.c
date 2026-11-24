
#include <sock/socket.h>
#include <sock/conn.h>
#include <kanawha/syscall.h>
#include <kanawha/pipe.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct sock_socket
{
    int fd;
};

struct sock_socket *
sock_create_socket(void)
{
    int res;
    int fd;
    res = kanawha_sys_pipe(
            PIPE_MUX,
            0,
            &fd);
    if(res) {
        return NULL;
    }
    
    struct sock_socket *sock;
    sock = sock_open_socket(fd);
    if(sock == NULL) {
        kanawha_sys_close(fd);
        return NULL;
    }

    return sock;
}

struct sock_socket *
sock_open_socket(int fd)
{
    struct sock_socket *sock;

    sock = malloc(sizeof(*sock));
    if(sock == NULL) {
        return NULL;
    }
    memset(sock, 0, sizeof(*sock));

    sock->fd = fd;

    return sock;
}
int
sock_close_socket(
        struct sock_socket *sock)
{
    kanawha_sys_close(sock->fd);
    free(sock);
    return 0;
}

int
sock_set_env_socket(
        struct sock_socket *socket,
        const char *env)
{
#define BUFLEN 64
    char buf[BUFLEN];
    snprintf(buf, BUFLEN, "%ld", (long)socket->fd);
    buf[BUFLEN-1] = '\0';
    setenv(env, buf, 1);
#undef BUFLEN
}

struct sock_socket *
sock_open_env_socket(
        const char *env)
{
    const char *str = getenv(env);
    if(str == NULL) {
        return NULL;
    }
    int fd = strtoul(str, 0, 0);
    return sock_open_socket(fd);
}

struct sock_conn *
sock_accept(
        struct sock_socket *sock)
{
    int res;
    int fd;

    res = kanawha_sys_accept(
            sock->fd,
            &fd,
            0);
    if(res) {
        return NULL;
    }

    struct sock_conn *conn;
    conn = sock_open_server_conn(fd);
    if(conn == NULL) {
        kanawha_sys_close(fd);
        return NULL;
    }

    return conn;
}
struct sock_conn *
sock_connect(
        struct sock_socket *sock)
{
    int res;
    int fd;

    res = kanawha_sys_connect(
            sock->fd,
            &fd,
            0);
    if(res) {
        return NULL;
    }

    struct sock_conn *conn;
    conn = sock_open_client_conn(fd);
    if(conn == NULL) {
        kanawha_sys_close(fd);
        return NULL;
    }

    return conn;
}
