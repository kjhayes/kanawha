#ifndef __KANAWHA__SOCK_CONNECTION_H__
#define __KANAWHA__SOCK_CONNECTION_H__

#include <semaphore.h>
#include <sock/msg.h>
#include <threads.h>

struct sock_msg_buffer;

struct sock_connection
{
    struct sock_msg_buffer *recv_buffer;
    struct sock_msg_buffer *send_buffer;

    sem_t read_lock;
    sem_t write_lock;

    thrd_t read_thread;
    thrd_t write_thread;

    int conn_fd;

    unsigned autopoll : 1;

    int(*recv_callback)(struct sock_connection *conn,
                        struct sock_msg *msg,
                        void *state);
    void *recv_callback_state;


    enum {
        SOCK_CONNECTION_CONNECTED,
        SOCK_CONNECTION_DISCONNECTED,
    } status;
};

int
sock_connection_init(
        struct sock_connection *conn,
        int conn_fd);

int
sock_connection_deinit(
        struct sock_connection *conn);

// Queues the message in the send_buffer
int
sock_connection_send_msg(
        struct sock_connection *conn,
        uint8_t type,
        uint8_t index,
        void *data,
        size_t datalen);

int
sock_connection_set_callback(
        struct sock_connection *conn,
        int(*on_recv)(struct sock_connection *conn,
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
sock_connection_start_autopoll(
        struct sock_connection *conn);
int
sock_connection_stop_autopoll(
        struct sock_connection *conn);

// Polls the receive buffer and handles a single
// msg if any are available (non-blocking
// if the registered callback is non-blocking)
int
sock_connection_poll(
        struct sock_connection *conn);

// Read from the connection until a msg arrives
// and save the message into the connection recv_buffer.
int
sock_connection_await_msg(
        struct sock_connection *conn);

// Write one message from the send buffer
// out to the connection fully.
int
sock_connection_flush_msg(
        struct sock_connection *conn);

// Map a region of the connection's shared
// memory address space into the current process.
int
sock_connection_map_shmem(
        struct sock_connection *conn,
        size_t offset,
        size_t size,
        void **base_out);
// Must be called with the same offset/size
// as "map_shmem" was called with.
int
sock_connection_unmap_shmem(
        struct sock_connection *conn,
        size_t offset,
        size_t size,
        void *base);

#endif
