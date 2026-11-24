
#include <sock/conn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <semaphore.h>

struct conn_ctrl {
    enum {
        SOCK_CONN_UNINIT = 0,
        SOCK_CONN_INIT   = 0x50CC,
    } status;

    struct {
        sem_t lock;
        unsigned long offset;
        unsigned long length;
    } buffers[SOCK_CONN_MAX_BUFFERS];
};

struct sock_conn {
    int fd;
    struct conn_ctrl *ctrl;
};

static inline struct sock_conn *
sock_raw_open_conn(int fd)
{
    struct sock_conn *conn = malloc(sizeof(*conn));
    if(conn == NULL) {
        return NULL;
    }
    memset(conn, 0, sizeof(*conn));
    conn->fd = fd;
    conn->ctrl = mmap(
            NULL,
            sizeof(*conn->ctrl),
            PROT_READ|PROT_WRITE,
            MMAP_SHARED,
            conn->fd,
            0);
    if(conn->ctrl == MAP_FAILED) {
        free(conn);
        return NULL;
    }

    // Should be done by the kernel, but lets be extra safe...
    memset(conn->ctrl, 0, sizeof(struct conn_ctrl));

    return conn;
}
static inline int
sock_raw_close_conn(
        struct sock_conn *conn)
{
    munmap(conn->ctrl, sizeof(*conn->ctrl));
    close(conn->fd);
    free(conn);
    return 0;
}

struct sock_conn *
sock_open_server_conn(
        int fd)
{
    struct sock_conn *conn;
    conn = sock_raw_open_conn(fd);
    if(conn == NULL) {
        return NULL;
    }

    // Should already be set, just double check
    conn->ctrl->status = SOCK_CONN_UNINIT;

    // Initialize each buffer
    for(size_t i = 0; i < SOCK_CONN_MAX_BUFFERS; i++) {
        sem_init(&conn->ctrl->buffers[i].lock, 1, 1);
        conn->ctrl->buffers[i].offset = 0;
        conn->ctrl->buffers[i].length = 0;
    }

    return conn;
}
struct sock_conn *
sock_open_client_conn(
        int fd)
{
    struct sock_conn *conn;
    conn = sock_raw_open_conn(fd);
    if(conn == NULL) {
        return NULL;
    }

    while(conn->ctrl->status == SOCK_CONN_UNINIT) {
        // Busy wait for the server to setup
        // the "conn_ctrl" header region
    }

    if(conn->ctrl->status != SOCK_CONN_INIT) {
        sock_raw_close_conn(conn);
        return NULL;
    }

    return conn;
}
int
sock_close_conn(
        struct sock_conn *conn)
{
    int res;
    res = sock_raw_close_conn(conn);
    if(res) {
        return res;
    }
    return 0;
}

int
sock_configure_buffer(
        struct sock_conn *conn,
        unsigned long index,
        unsigned long length)
{
    if(conn->ctrl->status != SOCK_CONN_UNINIT) {
        return -EINVAL;
    }
    if(index >= SOCK_CONN_MAX_BUFFERS) {
        return -EINVAL;
    }
    conn->ctrl->buffers[index].offset = 0;
    conn->ctrl->buffers[index].length = length;
    return 0;
}

int
sock_conn_finalize_config(
        struct sock_conn *conn)
{
    if(conn->ctrl->status != SOCK_CONN_UNINIT) {
        return -EINVAL;
    }

    // Allocate offsets for each buffer
    unsigned long offset = sizeof(struct conn_ctrl);
    for(size_t i = 0; i < SOCK_CONN_MAX_BUFFERS; i++) {
        unsigned long length = conn->ctrl->buffers[i].length;
        if(length == 0) {
            continue;
        }

        // Align up to a "page"
        unsigned long mask = (1UL<<SOCK_BUFFER_ALIGN_ORDER)-1;
        offset += mask;
        offset &= ~mask;

        conn->ctrl->buffers[i].offset = offset;
        offset += length;
    }

    conn->ctrl->status = SOCK_CONN_INIT;
    return 0;
}

static inline int
sock_conn_lock_buffer(
        struct sock_conn *conn,
        unsigned long index)
{
    if(index >= SOCK_CONN_MAX_BUFFERS) {
        return -EINVAL;
    }
    while(sem_wait(&conn->ctrl->buffers[index].lock)) {}
}
static inline int
sock_conn_unlock_buffer(
        struct sock_conn *conn,
        unsigned long index)
{
    if(index >= SOCK_CONN_MAX_BUFFERS) {
        return -EINVAL;
    }
    while(sem_post(&conn->ctrl->buffers[index].lock)) {}
}

struct sock_buffer
{
    struct sock_conn *conn;
    unsigned long index;
    void *mmap_region;
    unsigned long offset;
    unsigned long length;
};

struct sock_buffer *
sock_open_buffer(
        struct sock_conn *conn,
        unsigned long index)
{
    if(conn->ctrl->status != SOCK_CONN_INIT) {
        return NULL;
    }
    if(index >= SOCK_CONN_MAX_BUFFERS) {
        return NULL;
    }
    unsigned long length = conn->ctrl->buffers[index].length;
    unsigned long offset = conn->ctrl->buffers[index].offset;
    int fd = conn->fd;

    struct sock_buffer *buffer = malloc(sizeof(*buffer));
    if(buffer == NULL) {
        return NULL;
    }

    buffer->conn = conn;
    buffer->index = index;
    buffer->offset = offset;
    buffer->length = length;

    buffer->mmap_region = mmap(
            NULL,
            buffer->length,
            PROT_READ|PROT_WRITE,
            MMAP_SHARED,
            fd,
            buffer->offset);
    if(buffer->mmap_region == MAP_FAILED) {
        free(buffer);
        return NULL;
    }
    return buffer;
}
int
sock_close_buffer(
        struct sock_buffer *buffer)
{
    munmap(buffer->mmap_region, buffer->length);
    free(buffer);
    return 0;
}

int
sock_lock_buffer(
        struct sock_buffer *buffer)
{
    return sock_conn_lock_buffer(
            buffer->conn,
            buffer->index);
}
int
sock_unlock_buffer(
        struct sock_buffer *buffer)
{
    return sock_conn_unlock_buffer(
            buffer->conn,
            buffer->index);
}

void *
sock_buffer_raw_view(
        struct sock_buffer *buffer)
{
    return buffer->mmap_region;
}
unsigned long
sock_buffer_raw_length(
        struct sock_buffer *buffer)
{
    return buffer->length;
}

static inline int
sock_buffer_bounds_check(
        struct sock_buffer *buffer,
        unsigned long offset,
        unsigned long len)
{
    if(offset + len > buffer->length) {
        return -EINVAL;
    }
    return 0;
}

int
sock_buffer_read(
        struct sock_buffer *buffer,
        unsigned long offset,
        void *data,
        unsigned long len)
{
    int res;
    res = sock_buffer_bounds_check(buffer, offset, len);
    if(res) {
        return res;
    }

    memcpy(data, buffer->mmap_region + offset, len);

    return 0;
}
int
sock_buffer_write(
        struct sock_buffer *buffer,
        unsigned long offset,
        void *data,
        unsigned long len)
{
    int res;
    res = sock_buffer_bounds_check(buffer, offset, len);
    if(res) {
        return res;
    }

    memcpy(buffer->mmap_region + offset, data, len);

    return 0;
}

int
sock_buffer_memset(
        struct sock_buffer *buffer,
        unsigned long offset,
        int c,
        unsigned long len)
{
    int res;
    res = sock_buffer_bounds_check(buffer, offset, len);
    if(res) {
        return res;
    }

    memset(buffer->mmap_region + offset, c, len);

    return 0;
}

