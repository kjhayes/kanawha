
#include <lens/internal.h>
#include <lens/window.h>
#include <lens/input_buffer.h>
#include <lens/gfx.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sock/sock.h>

static inline int
lens_window_handle_notify_gfx_info(
        struct lens_window *window,
        struct sock_msg *msg)
{
    int res;

    size_t len = msg->length;
    if(len < sizeof(struct lens_gfx_info)) {
        fprintf(stderr, "lens_window: received short NOTIFY_GFX_INFO message!\n");
        return -EINVAL;
    }
    struct lens_gfx_info *msg_info = (void*)msg->data;
    size_t num_layers = msg_info->num_layers;

    size_t min_size = sizeof(*msg_info) + (num_layers * sizeof(msg_info->layer_layout[0]));
    if(len < min_size) {
        fprintf(stderr, "lens_window: received invalid NOTIFY_GFX_INFO message!\n");
        return -EINVAL;
    }

    struct lens_gfx_info *info = malloc(min_size);
    if(info == NULL) {
        fprintf(stderr, "lens_window: out of memory during NOTIFY_GFX_INFO message!\n");
        return -ENOMEM;
    }

    memcpy(info, msg_info, min_size);

    while(sem_wait(&window->gfx_lock)) {}

    if(window->gfx_info) {
        if(window->gfx_info->frame_size > 0) {
            sock_connection_unmap_shmem(
                    &window->conn,
                    0,
                    window->gfx_info->frame_size,
                    window->gfx_frame);
        }
        free(window->gfx_info);
    }

    if(info->frame_size > 0) {
        res = sock_connection_map_shmem(
                &window->conn,
                0,
                info->frame_size,
                &window->gfx_frame);
        if(res) {
            fprintf(stderr, "lens_window: failed to map frame during NOTIFY_GFX_INFO message!\n");
            free(info);
            sem_post(&window->gfx_lock);
            return res;
        }
    }
    window->gfx_info = info;

    sem_post(&window->gfx_lock);
    return 0;
}

static int
lens_window_on_recv(
        struct sock_connection *conn,
        struct sock_msg *msg,
        void *state)
{
    int res;

    struct lens_window *window =
        container_of(conn, struct lens_window, conn);
    
    unsigned long old;

    switch(msg->type) {
        case LENS_MSG_FLUSH_ACK:
            old = __atomic_fetch_and(&window->flush_req_count, 0, __ATOMIC_SEQ_CST);
            if(old > 1) {
                res = lens_window_flush(window);
                if(res) {
                    return res;
                }
            }
            break;
        case LENS_MSG_INPUT_EVT:
            if(msg->length != sizeof(struct input_event)) {
                return -EINVAL;
            }
            lens_input_buffer_push(
                    window->input_buffer,
                    (struct input_event*)msg->data);
            break;
        case LENS_MSG_NOTIFY_GFX_INFO:
            res = lens_window_handle_notify_gfx_info(window, msg);
            if(res) {
                return res;
            }
            break;
        default:
            fprintf(stderr, "lens_window_on_recv: unrecognized message type %d!\n",
                    (int)msg->type);
            return -EINVAL;
    }
    return 0;
}

struct lens_window *
lens_open_window(void)
{
    int res;

    struct lens_window *window;
    window = malloc(sizeof(*window));
    if(window == NULL) {
        return NULL;
    }

    window->flush_req_count = 0;

    sem_init(&window->gfx_lock, 1, 1);
    window->gfx_info = NULL;
    window->gfx_frame = NULL;

    window->input_buffer = lens_create_input_buffer(64);
    if(window->input_buffer == NULL) {
        sem_destroy(&window->gfx_lock);
        free(window);
        return NULL;
    }

    res = sock_open_client_connection(
            __lens_socket,
            &window->conn);
    if(res) {
        sem_destroy(&window->gfx_lock);
        lens_destroy_input_buffer(window->input_buffer);
        free(window);
        return NULL;
    }

    return window;
}

int
lens_close_window(
        struct lens_window *window)
{
    sem_destroy(&window->gfx_lock);
    if(window->gfx_info != NULL) {
        if(window->gfx_info->frame_size > 0) {
            sock_connection_unmap_shmem(
                    &window->conn,
                    0,
                    window->gfx_info->frame_size,
                    window->gfx_frame);
        }
        free(window->gfx_info);
        window->gfx_info = NULL;
        window->gfx_frame = NULL;
    }
    sock_close_client_connection(&window->conn);
    lens_destroy_input_buffer(window->input_buffer);
    free(window);
    return 0;
}

int
lens_window_flush(
        struct lens_window *window)
{
    int res;

    unsigned long old = __atomic_fetch_add(&window->flush_req_count, 1, __ATOMIC_SEQ_CST);

    if(old > 0) {
        return 0;
    }
    res = sock_connection_send_msg(
            &window->conn,
            LENS_MSG_FLUSH_REQ,
            0,
            NULL,
            0);
    if(res) {
        __atomic_fetch_and(&window->flush_req_count, 0, __ATOMIC_SEQ_CST);
        return res;
    }
    return 0;
}

int
lens_window_poll(
        struct lens_window *window)
{
    int res;
    res = sock_connection_poll(&window->conn, lens_window_on_recv, NULL);
    if(res) {
        return res;
    }
    return 0;
}

// 0 -> no event
// 1 -> *evt is now valid
// <0 -> errno
int
lens_window_get_input(
        struct lens_window *window,
        struct input_event *evt)
{
    return lens_input_buffer_pop(
            window->input_buffer,
            evt);
}

// 0 -> no event
// 1 -> could read an event without blocking
// <0 -> errno
int
lens_window_peek_input(
        struct lens_window *window)
{
    return lens_input_buffer_peek(
            window->input_buffer);
}

int
lens_window_lock_gfx(
        struct lens_window *window)
{
    while(sem_wait(&window->gfx_lock)) {}
}
int
lens_window_unlock_gfx(
        struct lens_window *window)
{
    sem_post(&window->gfx_lock);
}

static struct lens_gfx_info
default_lens_gfx_info = {
    .frame_size = 0,
    .num_layers = 0,
};

struct lens_gfx_info *
lens_window_get_gfx_info(
        struct lens_window *window)
{
    if(window->gfx_info == NULL) {
        return &default_lens_gfx_info;
    } else {
        return window->gfx_info;
    }
}

void*
lens_window_get_gfx_frame(
        struct lens_window *window)
{
    return window->gfx_frame;
}
