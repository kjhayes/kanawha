#ifndef __SOCK__SOCKET_H__
#define __SOCK__SOCKET_H__

struct sock_socket;

struct sock_socket *
sock_create_socket(void);
struct sock_socket *
sock_open_socket(int fd);
int
sock_close_socket(
        struct sock_socket *);

int
sock_set_env_socket(
        struct sock_socket *socket,
        const char *env);

struct sock_socket *
sock_open_env_socket(
        const char *env);

struct sock_conn *
sock_accept(
        struct sock_socket *);
struct sock_conn *
sock_connect(
        struct sock_socket *);
// Defined in "conn.[ch]"
int
sock_close_conn(
        struct sock_conn *);

#endif
