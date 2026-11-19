#ifndef __KANAWHA__SOCK_SOCK_H__
#define __KANAWHA__SOCK_SOCK_H__

#include <sock/msg.h>
#include <sock/conn.h>

struct sock_conn;
struct sock_socket;
struct sock_msg;

int
sock_create_socket(const char *name);

struct sock_socket *
sock_open_socket(const char *name);
int
sock_close_socket(struct sock_socket *sock);

// Client
int
sock_open_client_conn(
        struct sock_socket *socket,
        struct sock_conn *conn
        );
int
sock_close_client_conn(
        struct sock_conn *conn);

// Server
int
sock_open_server_conn(
        struct sock_socket *socket,
        struct sock_conn *conn
        );
int
sock_close_server_conn(
        struct sock_conn *conn);

#endif
