
#include <sock/conn.h>
#include <sock/msgbuf.h>
#include <stdlib.h>
#include <errno.h>
#include <semaphore.h>

struct msgbuf_ctrl
{
    enum {
        SOCK_MSGBUF_UNINIT = 0,
        SOCK_MSGBUF_INIT = 0x3E56B0FF,
    } status;

    sem_t empty_slots;
    sem_t full_slots;

    unsigned long head;
    unsigned long tail;

    __attribute__((aligned(16)))
    unsigned char data[];
};

struct sock_msgbuf {
    struct sock_buffer *buffer;
    unsigned long slot_size;
    unsigned long num_slots;
    struct msgbuf_ctrl *ctrl;
};

int
sock_configure_msgbuf(
        struct sock_conn *conn,
        unsigned long index,
        unsigned long max_size,
        unsigned long num_slots)
{
    return sock_configure_buffer(
            conn,
            index,
            sizeof(struct msgbuf_ctrl) + (max_size * num_slots));
}

struct sock_msgbuf *
sock_open_msgbuf(
        struct sock_conn *conn,
        unsigned long index,
        unsigned long max_size)
{
    struct sock_msgbuf *msgbuf;
    msgbuf = malloc(sizeof(*msgbuf));
    if(msgbuf == NULL) {
        return NULL;
    }

    struct sock_buffer *buffer;
    buffer = sock_open_buffer(conn, index);
    if(buffer == NULL)
    {
        free(msgbuf);
        return NULL;
    }
    msgbuf->buffer = buffer;
    msgbuf->ctrl = sock_buffer_raw_view(buffer);
    unsigned long length = sock_buffer_raw_length(buffer);
    if(length <= sizeof(struct msgbuf_ctrl)) {
        sock_close_buffer(buffer);
        free(msgbuf);
        return NULL;
    }
    unsigned long datalen = length - sizeof(struct msgbuf_ctrl);
    msgbuf->slot_size = max_size;
    msgbuf->num_slots = datalen / msgbuf->slot_size;
    if(msgbuf->num_slots <= 0) {
        sock_close_buffer(buffer);
        free(msgbuf);
        return NULL;
    }

    sock_lock_buffer(msgbuf->buffer);

    if(msgbuf->ctrl->status == SOCK_MSGBUF_UNINIT) {
        // Initialize the buffer
        sem_init(&msgbuf->ctrl->empty_slots, 1, msgbuf->num_slots);
        sem_init(&msgbuf->ctrl->full_slots, 1, 0);
        msgbuf->ctrl->head = 0;
        msgbuf->ctrl->tail = 0;
        msgbuf->ctrl->status = SOCK_MSGBUF_INIT;
    }

    if(msgbuf->ctrl->status != SOCK_MSGBUF_INIT) {
        sock_unlock_buffer(msgbuf->buffer);
        sock_close_buffer(buffer);
        free(msgbuf);
        return NULL;
    }

    sock_unlock_buffer(msgbuf->buffer);

    return msgbuf;
}
int
sock_close_msgbuf(
        struct sock_msgbuf *msgbuf)
{
    sock_close_buffer(msgbuf->buffer);
    free(msgbuf);
    return 0;
}

unsigned long
sock_msgbuf_num_slots(
        struct sock_msgbuf *msgbuf)
{
    return msgbuf->num_slots;
}

static inline unsigned long
sock_msgbuf_get_slot_offset(
        struct sock_msgbuf *msgbuf,
        unsigned long index)
{
    return sizeof(struct msgbuf_ctrl) + (index * msgbuf->slot_size);
}

int
sock_msgbuf_send(
        struct sock_msgbuf *msgbuf,
        void *msg,
        unsigned long msglen)
{
    int res;

    if(msglen > msgbuf->slot_size) {
        return -EINVAL;
    }

    // Claim a slot
    while(sem_wait(&msgbuf->ctrl->empty_slots)) {}

    // There *must* be an empty slot at "head" now
    unsigned long head = msgbuf->ctrl->head;

    unsigned long offset;
    offset = sock_msgbuf_get_slot_offset(msgbuf, head);
    res = sock_buffer_write(msgbuf->buffer, offset, msg, msglen);
    if(res) {
        sem_post(&msgbuf->ctrl->empty_slots);
        return res;
    }

    msgbuf->ctrl->head = (head + 1) % msgbuf->num_slots;

    // Notify that the msg is available
    sem_post(&msgbuf->ctrl->full_slots);
    return 0;
}

int
sock_msgbuf_recv(
        struct sock_msgbuf *msgbuf,
        void *buffer,
        unsigned long buflen)
{
    int res;

    if(buflen > msgbuf->slot_size) {
        return -EINVAL;
    }

    // Claim a msg
    while(sem_wait(&msgbuf->ctrl->full_slots)) {}

    // There *must* be a message in the slot at "tail" now
    unsigned long tail = msgbuf->ctrl->tail;

    unsigned long offset;
    offset = sock_msgbuf_get_slot_offset(msgbuf, tail);
    res = sock_buffer_read(msgbuf->buffer, offset, buffer, buflen);
    if(res) {
        sem_post(&msgbuf->ctrl->full_slots);
        return res;
    }

    msgbuf->ctrl->tail = (tail + 1) % msgbuf->num_slots;

    // Notify that a slot is available
    sem_post(&msgbuf->ctrl->empty_slots);
    return 0;
}

