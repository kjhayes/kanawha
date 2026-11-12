#ifndef __NOOK__NOOK_H__
#define __NOOK__NOOK_H__

#include <stddef.h>

struct nook;
struct nook_conn;

struct nook *
nook_create(
        const char *name);

struct nook *
nook_open(
        const char *name);
int
nook_close(
        struct nook *nook);

struct nook_conn *
nook_connect_conn(
        struct nook *nook);
struct nook_conn *
nook_accept_conn(
        struct nook *nook);
int
nook_close_conn(
        struct nook_conn *conn);

int
nook_conn_send(
        struct nook_conn *conn,
        void *buffer,
        size_t buflen);
int
nook_conn_recv(
        struct nook_conn *conn,
        void *buffer,
        size_t buflen);

#endif
