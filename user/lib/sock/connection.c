
#include <sock/connection.h>
#include <sock/sock.h>
#include <sock/msg.h>

#include <kanawha/sys-wrappers.h>

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define PAGE_ORDER 12

// Message Buffers
struct sock_buffered_msg {
    struct sock_buffered_msg *next;
    struct sock_msg msg;
};

static inline struct sock_buffered_msg *
sock_buffered_msg_alloc(
        size_t datalen)
{
    return malloc(sizeof(struct sock_buffered_msg) + datalen);
}

struct sock_msg_buffer {
    sem_t lock;
    sem_t enqueued_count;
    struct sock_buffered_msg *head;
    struct sock_buffered_msg *tail;
};

static inline int
sock_buffered_msg_free(
        struct sock_buffered_msg *msg)
{
    free(msg);
    return 0;
}

static inline struct sock_buffered_msg *
sock_msg_buffer_pop_head(
        struct sock_msg_buffer *buf)
{
    struct sock_buffered_msg *msg;
    while(sem_wait(&buf->enqueued_count));
    sem_wait(&buf->lock);
    msg = buf->head;
    if(msg != NULL) {
        buf->head = msg->next;
        if(buf->head == NULL) {
            buf->tail = NULL;
        }
    }
    sem_post(&buf->lock);
    return msg;
}

static inline struct sock_buffered_msg *
sock_msg_buffer_try_pop_head(
        struct sock_msg_buffer *buf)
{
    int res;
    struct sock_buffered_msg *msg;
    res = sem_trywait(&buf->enqueued_count);
    if(res) {
        return NULL;
    }
    // We have claimed an entry
    sem_wait(&buf->lock);
    msg = buf->head;
    if(msg != NULL) {
        // This should not block
        buf->head = msg->next;
        if(buf->head == NULL) {
            buf->tail = NULL;
        }
    } else {
        // This shouldn't be possible...
        fprintf(stderr, "sock: failed to get claimed socket msg! (shouldn't be possible!)\n");
    }
    sem_post(&buf->lock);
    return msg;
}

static inline int
sock_msg_buffer_push_tail(
        struct sock_msg_buffer *buf,
        struct sock_buffered_msg *msg)
{
    sem_wait(&buf->lock);
    msg->next = NULL;
    if(buf->head == NULL) {
        buf->head = msg;
    } else {
        buf->tail->next = msg;
    }
    buf->tail = msg;
    sem_post(&buf->enqueued_count);
    sem_post(&buf->lock);
    return 0;
}

static inline struct sock_msg_buffer *
sock_msg_buffer_create(void)
{
    int res;
    struct sock_msg_buffer *buf = malloc(sizeof(*buf));
    if(buf == NULL) {
        return NULL;
    }
    res = sem_init(&buf->lock, 1, 1);
    if(res) {
        free(buf);
        return NULL;
    }
    res = sem_init(&buf->enqueued_count, 1, 0);
    if(res) {
        sem_destroy(&buf->lock);
        free(buf);
        return NULL;
    }
    buf->head = NULL;
    buf->tail = NULL;
    return buf;
}

static inline int
sock_msg_buffer_destroy(
        struct sock_msg_buffer *buf)
{
    struct sock_buffered_msg *msg;
    while(1) {
        msg = sock_msg_buffer_pop_head(buf);
        if(msg == NULL) {
            break;
        }
        sock_buffered_msg_free(msg);
    }

    sem_destroy(&buf->enqueued_count);
    sem_destroy(&buf->lock);
    free(buf);
    return 0;
}

// Connections

static int
sock_connection_read_thread(void *_conn)
{
    int res;
    struct sock_connection *conn = _conn;
    while(conn->status == SOCK_CONNECTION_CONNECTED) {
        res = sock_connection_await_msg(conn);
        if(res) {
            // Weird but we will ignore it...
        }
    }
    return 0;
}

static int
sock_connection_write_thread(void *_conn)
{
    int res;
    struct sock_connection *conn = _conn;
    while(conn->status == SOCK_CONNECTION_CONNECTED) {
        res = sock_connection_flush_msg(conn);
        if(res) {
            // Weird but we will ignore it...
        }
        // Writes are non-blocking for now...
        usleep(10000); // 10ms sleep
    }
    return 0;
}

int
sock_connection_init(
        struct sock_connection *conn,
        int conn_fd)
{
    int res;

    res = kanawha_sys_faccess(
            conn->conn_fd,
            FACCESS_NON_BLOCKING,
            FACCESS_MODE_CLEAR);
    if(res) {
        return res;
    }
            
    res = sem_init(&conn->read_lock, 1, 1);
    if(res) {
        return res;
    }
    res = sem_init(&conn->write_lock, 1, 1);
    if(res) {
        sem_destroy(&conn->read_lock);
        return res;
    }

    conn->recv_buffer = sock_msg_buffer_create();
    if(conn->recv_buffer == NULL) {
        sem_destroy(&conn->read_lock);
        sem_destroy(&conn->write_lock);
        return -ENOMEM;
    }
    conn->send_buffer = sock_msg_buffer_create();
    if(conn->send_buffer == NULL) {
        sem_destroy(&conn->read_lock);
        sem_destroy(&conn->write_lock);
        sock_msg_buffer_destroy(conn->recv_buffer);
        return -ENOMEM;
    }

    conn->conn_fd = conn_fd;
    conn->status = SOCK_CONNECTION_CONNECTED;

    res = thrd_create(&conn->read_thread, sock_connection_read_thread, conn);
    if(res) {
        sem_destroy(&conn->read_lock);
        sem_destroy(&conn->write_lock);
        sock_msg_buffer_destroy(conn->recv_buffer);
        sock_msg_buffer_destroy(conn->send_buffer);
        return res;
    }
    res = thrd_create(&conn->write_thread, sock_connection_write_thread, conn);
    if(res) {
        int read_exit;
        thrd_join(conn->read_thread, &read_exit);
        sem_destroy(&conn->read_lock);
        sem_destroy(&conn->write_lock);
        sock_msg_buffer_destroy(conn->recv_buffer);
        sock_msg_buffer_destroy(conn->send_buffer);
        return res;
    }

    return 0;
}

int
sock_connection_deinit(
        struct sock_connection *conn)
{
    conn->status = SOCK_CONNECTION_DISCONNECTED;
    int read_exit, write_exit;
    thrd_join(conn->read_thread, &read_exit);
    thrd_join(conn->write_thread, &write_exit);
    sem_destroy(&conn->read_lock);
    sem_destroy(&conn->write_lock);
    sock_msg_buffer_destroy(conn->recv_buffer);
    sock_msg_buffer_destroy(conn->send_buffer);
    return 0;
}

__attribute__((unused))
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

    struct sock_buffered_msg *msg;
    msg = sock_buffered_msg_alloc(datalen);
    if(msg == NULL) {
        return -ENOMEM;
    }
    msg->msg.type = type;
    msg->msg.index = index;
    msg->msg.length = datalen;
    memcpy(msg->msg.data, data, datalen);

    res = sock_msg_buffer_push_tail(
            conn->send_buffer,
            msg);
    if(res) {
        sock_buffered_msg_free(msg);
        return res;
    }

    return 0;
}

int
sock_connection_poll(
        struct sock_connection *conn,
        int(*on_recv)(struct sock_connection *conn,
                      struct sock_msg *msg,
                      void *state),
        void *state)
{
    int res;

    struct sock_buffered_msg *msg;
    msg = sock_msg_buffer_try_pop_head(
            conn->recv_buffer);
    if(msg == NULL) {
        return 0;
    }

    if(on_recv != NULL) {
        res = (*on_recv)(conn,
                   &msg->msg,
                   state);
    } else {
        res = 0;
    }
    sock_buffered_msg_free(msg);
    return res;
}

int
sock_connection_await_msg(
        struct sock_connection *conn)
{
    int res;

    if(conn->status != SOCK_CONNECTION_CONNECTED) {
        return -EINVAL;
    }

    struct sock_msg msg;
    sem_wait(&conn->read_lock);

    { // Read a sock_msg header
        ssize_t total = 0;
        while(total < sizeof(msg)) {
            ssize_t amt = read(conn->conn_fd, ((void*)&msg) + total, sizeof(msg) - total);
            if(amt <= 0) {
                sem_post(&conn->read_lock);
                return -EFAULT;
            }
            total += amt;
        }
    }

    struct sock_buffered_msg *buffer =
        sock_buffered_msg_alloc(msg.length);
    if(buffer == NULL) {
        sem_post(&conn->read_lock);
        return -ENOMEM;
    }

    memcpy(&buffer->msg, &msg, sizeof(msg));

    { // Read in the rest of the data

        ssize_t total = 0;
        while(total < msg.length) {
            ssize_t amt = read(conn->conn_fd, buffer->msg.data + total, msg.length - total);
            if(amt <= 0) {
                sem_post(&conn->read_lock);
                free(buffer);
                return -EINVAL;
            }
            total += amt;
        }
    }

    res = sock_msg_buffer_push_tail(
            conn->recv_buffer,
            buffer);
    if(res) {
        sem_post(&conn->read_lock);
        sock_buffered_msg_free(buffer);
        return res;
    }

    sem_post(&conn->read_lock);

    return 0;
}

int
sock_connection_flush_msg(
        struct sock_connection *conn)
{
    int res;

    sem_wait(&conn->write_lock);

    struct sock_buffered_msg *buffer;
    buffer = sock_msg_buffer_pop_head(
            conn->send_buffer);
    if(buffer == NULL) {
        sem_post(&conn->write_lock);
        return 0;
    }

    struct sock_msg *msg = &buffer->msg;

    ssize_t amt;
    ssize_t total = 0;
    ssize_t desired = sizeof(struct sock_msg) + buffer->msg.length;

    while(total < desired)
    {
        amt = write(conn->conn_fd,((void*)msg)+total,desired-total);
        if(amt < 0) {
            sem_post(&conn->write_lock);
            return amt;
        }
        total += amt;
    }

    sem_post(&conn->write_lock);

    return 0;
}

int
sock_connection_map_shmem(
        struct sock_connection *conn,
        size_t offset,
        size_t size,
        void **base_out)
{
    int res;
    size +=  ((1ULL<<PAGE_ORDER)-1);
    size &= ~((1ULL<<PAGE_ORDER)-1);
    res = kanawha_sys_mmap(conn->conn_fd,
                           offset,
                           base_out,
                           size,
                           MMAP_SHARED | MMAP_PROT_READ | MMAP_PROT_WRITE);
    if(res) {
        return res;
    }
    return 0;
}

int
sock_connection_unmap_shmem(
        struct sock_connection *conn,
        size_t offset,
        size_t size,
        void *base)
{
    int res;

    size +=  ((1ULL<<PAGE_ORDER)-1);
    size &= ~((1ULL<<PAGE_ORDER)-1);

    res = kanawha_sys_munmap(base);
    if(res) {
        return res;
    }
    return 0;
}

