#ifndef __SOCK__MSGBUF_H__
#define __SOCK__MSGBUF_H__

#include <stdlib.h>

struct sock_conn;
struct sock_msgbuf;

int
sock_configure_msgbuf(
        struct sock_conn *conn,
        unsigned long index,
        unsigned long max_size,
        unsigned long num_slots);

struct sock_msgbuf *
sock_open_msgbuf(
        struct sock_conn *conn,
        unsigned long index,
        unsigned long max_size);
int
sock_close_msgbuf(
        struct sock_msgbuf *msgbuf);

unsigned long
sock_msgbuf_num_slots(
        struct sock_msgbuf *msgbuf);

int
sock_msgbuf_send(
        struct sock_msgbuf *msgbuf,
        void *msg,
        unsigned long msglen);

int
sock_msgbuf_recv(
        struct sock_msgbuf *msgbuf,
        void *buffer,
        unsigned long buflen);

#endif
