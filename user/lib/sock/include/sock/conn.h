#ifndef __KANAWHA__SOCK_CONNECTION_H__
#define __KANAWHA__SOCK_CONNECTION_H__

#include <semaphore.h>
#include <sock/msg.h>
#include <threads.h>

struct sock_msg_buffer;
struct sock_conn;

int
sock_conn_init(
        struct sock_conn *conn,
        int conn_fd);

int
sock_conn_deinit(
        struct sock_conn *conn);

// Queues the message in the send_buffer
int
sock_conn_send_msg(
        struct sock_conn *conn,
        uint8_t type,
        uint8_t index,
        void *data,
        size_t datalen);

int
sock_conn_set_callback(
        struct sock_conn *conn,
        int(*on_recv)(struct sock_conn *conn,
                      struct sock_msg *msg,
                      void *state),
        void *state);

// Automatically call any registered callback when a msg is
// received, if no callback is registered, silently drops
// all incoming messages...
//
// If the callback is blocking, note: messages are handled fully
// sequentially e.g. the callback for a previous message must
// be processed before the next message's callback will begin.
int
sock_conn_start_autopoll(
        struct sock_conn *conn);
int
sock_conn_stop_autopoll(
        struct sock_conn *conn);

// Polls the receive buffer and handles a single
// msg if any are available (non-blocking
// if the registered callback is non-blocking)
int
sock_conn_poll(
        struct sock_conn *conn);

// Read from the conn until a msg arrives
// and save the message into the conn recv_buffer.
int
sock_conn_await_msg(
        struct sock_conn *conn);

// Write one message from the send buffer
// out to the conn fully.
int
sock_conn_flush_msg(
        struct sock_conn *conn);

// Map a region of the conn's shared
// memory address space into the current process.
int
sock_conn_map_shmem(
        struct sock_conn *conn,
        size_t offset,
        size_t size,
        void **base_out);
// Must be called with the same offset/size
// as "map_shmem" was called with.
int
sock_conn_unmap_shmem(
        struct sock_conn *conn,
        size_t offset,
        size_t size,
        void *base);

int
sock_conn_check_for_disconnect(
        struct sock_conn *conn);

#endif
