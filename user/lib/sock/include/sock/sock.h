#ifndef __KANAWHA__SOCK_SOCK_H__
#define __KANAWHA__SOCK_SOCK_H__

#include <sock/msg.h>
#include <sock/connection.h>

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
sock_open_client_connection(
        struct sock_socket *socket,
        struct sock_connection *conn
        );
int
sock_close_client_connection(
        struct sock_connection *conn);

// Server
int
sock_open_server_connection(
        struct sock_socket *socket,
        struct sock_connection *conn
        );
int
sock_close_server_connection(
        struct sock_connection *conn);

#endif
