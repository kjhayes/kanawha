
#include <windd/windd.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <kanawha/gfx.h>
#include <kanawha/input.h>
#include <kanawha/sys-wrappers.h>

#define WINDOW_MODE_CLIENT (0U)
#define WINDOW_MODE_SERVER (1U)

#define DEFAULT_INPUT_EVENT_BUFLEN 16

static int windd_inited = 0;
static int windd_socket = -1;

static int
window_init_common(
        struct window *win)
{
    win->disconnected = 0;

    win->read_lock = 0;
    win->write_lock = 0;

    win->buffer_lock = 0;
    win->buffer_size = 0;
    win->buffer = NULL;

    win->partial_msg = NULL;

    win->input_lock = 0;
    win->input_head = 0;
    win->input_tail = 0;
    win->input_buflen = 0;
    win->input_ringbuf = malloc(sizeof(struct input_event) * DEFAULT_INPUT_EVENT_BUFLEN);
    if(win->input_ringbuf != NULL) {
        win->input_buflen = DEFAULT_INPUT_EVENT_BUFLEN;
    }

    return 0;
}

static int
window_deinit_common(
        struct window *win)
{
    if(win->input_buflen > 0) {
        free(win->input_ringbuf);
    }
    return 0;
}

static int
windd_window_on_recv_input_msg(
        struct window *win,
        struct input_event *evt);

static int windd_window_pong(struct window *win, char recv_ping)
{
    struct window_msg msg = {
        .type = WINDD_MSG_TYPE_PONG,
        .datalen = 1,
    };

    windd_window_lock_write(win);
    write(win->conn, &msg, sizeof(msg));
    char pong = recv_ping + 1;
    write(win->conn, &pong, 1);
    windd_window_unlock_write(win);

    return 0;
}

static int
windd_generic_init(void)
{
    int res;
    int socket;
    {
        const char *socket_env = getenv("WINDD_SOCKET");
        if(socket_env == NULL)
        {
            return -ENXIO;
        }
        socket = strtoul(socket_env, NULL, 10);
    }

    res = kanawha_sys_faccess(socket, FACCESS_NON_BLOCKING, FACCESS_MODE_CLEAR);
    if(res)
    {
        return res;
    }

    windd_socket = socket;
    windd_inited = 1;
    return 0;
}

static int
windd_generic_deinit(void)
{
    if(!windd_inited) {
        return 0;
    }
    
    windd_socket = -1;
    windd_inited = 0;
}

int windd_client_init(void)
{
    if(windd_inited) {
        return 0;
    }
    return windd_generic_init();
}
int windd_client_deinit(void)
{
    if(!windd_inited) {
        return 0;
    }
    return windd_generic_deinit();
}

int windd_server_init(void)
{
    if(windd_inited) {
        return 0;
    }
    return windd_generic_init();
}
int windd_server_deinit(void)
{
    if(!windd_inited) {
        return 0;
    }
    return windd_generic_deinit();
}

struct window *
windd_server_await_connection(void)
{
    int res;
    int conn;

    if(!windd_inited) {
        return NULL;
    }

    res = kanawha_sys_accept(windd_socket, &conn, 0);
    if(res)
    {
        return NULL;
    }

    struct window *window = malloc(sizeof(struct window));
    if(window == NULL) {
        kanawha_sys_close(conn);
        return NULL;
    }

    window->mode = WINDOW_MODE_SERVER;
    window->conn = conn;

    window_init_common(window);

    return window;
}

int
windd_server_close_connection(struct window *window)
{
    kanawha_sys_close(window->conn);
    window_init_common(window);
    free(window);
    return 0;
}

int windd_window_lock_read(struct window *win)
{
    while(__atomic_fetch_or(&win->read_lock, 1, __ATOMIC_SEQ_CST)) {}
}
int windd_window_unlock_read(struct window *win)
{
    __atomic_fetch_and(&win->read_lock, 0, __ATOMIC_SEQ_CST);
}
int windd_window_lock_write(struct window *win)
{
    while(__atomic_fetch_or(&win->write_lock, 1, __ATOMIC_SEQ_CST)) {}
}
int windd_window_unlock_write(struct window *win)
{
    __atomic_fetch_and(&win->write_lock, 0, __ATOMIC_SEQ_CST);
}

int
windd_window_lock_buffer(struct window *win)
{
    while(__atomic_fetch_or(&win->buffer_lock, 1, __ATOMIC_SEQ_CST)) {}
}

int
windd_window_unlock_buffer(struct window *win)
{
    __atomic_fetch_and(&win->buffer_lock, 0, __ATOMIC_SEQ_CST);
}

struct window *windd_client_open(void)
{
    int res;
    int conn;

    if(!windd_inited) {
        return NULL;
    }

    res = kanawha_sys_connect(windd_socket, &conn, 0);
    if(res)
    {
        return NULL;
    }

    struct window *window = malloc(sizeof(struct window));
    if(window == NULL) {
        kanawha_sys_close(conn);
        return NULL;
    }

    window->mode = WINDOW_MODE_CLIENT;
    window->conn = conn;

    window_init_common(window);

    return window;
}

int windd_client_close(struct window *window)
{
    kanawha_sys_close(window->conn);
    window_init_common(window);
    free(window);
    return 0;
}

static inline int
windd_server_window_notify_layout(
        struct window *win)
{
    struct window_msg msg = {
        .type = WINDD_MSG_TYPE_SET_LAYOUT,
        .datalen = sizeof(struct gfx_layout),
    };

    if(win->layout_valid) {
        windd_window_lock_write(win);
        write(win->conn, &msg, sizeof(msg));
        write(win->conn, &win->layout, sizeof(struct gfx_layout));
        windd_window_unlock_write(win);
        return 0;
    } else {
        return -ENXIO;
    }
}
static inline int
windd_server_window_notify_position(
        struct window *win)
{
    struct window_msg msg = {
        .type = WINDD_MSG_TYPE_SET_POSITION,
        .datalen = sizeof(struct window_position),
    };

    if(win->position_valid) {
        windd_window_lock_write(win);
        write(win->conn, &msg, sizeof(msg));
        write(win->conn, &win->position, sizeof(struct window_position));
        windd_window_unlock_write(win);
        return 0;
    } else {
        return -ENXIO;
    }
}

static inline int
windd_window_on_recv_msg(
        struct window *win,
        struct window_msg *msg)
{
    int res = 0;
    switch(msg->type) {
        case WINDD_MSG_TYPE_SET_LAYOUT:
            if(win->mode == WINDOW_MODE_SERVER) {
                return -EINVAL;
            }
            if(msg->datalen != sizeof(win->layout)) {
                return -EINVAL;
            }
            memcpy(&win->layout, msg->data, sizeof(win->layout));
            win->layout_valid = 1;
            break;
        case WINDD_MSG_TYPE_SET_POSITION:
            if(win->mode == WINDOW_MODE_SERVER) {
                return -EINVAL;
            }
            if(msg->datalen != sizeof(struct window_position)) {
                return -EINVAL;
            }
            memcpy(&win->position, msg->data, sizeof(win->position));
            win->position_valid = 1;
            break;
        case WINDD_MSG_TYPE_REQ_LAYOUT:
            if(win->mode == WINDOW_MODE_CLIENT) {
                return -EINVAL;
            }
            res = windd_server_window_notify_layout(win);
            break;
        case WINDD_MSG_TYPE_REQ_POSITION:
            if(win->mode == WINDOW_MODE_CLIENT) {
                return -EINVAL;
            }
            res = windd_server_window_notify_position(win);
            break;

        case WINDD_MSG_TYPE_PING:
            if(msg->datalen != 1) {
                res = -EINVAL;
                break;
            }
            res = windd_window_pong(win, ((char*)msg->data)[0]);
            break;
        case WINDD_MSG_TYPE_PONG:
            if(msg->datalen != 1) {
                res = -EINVAL;
                break;
            }
            win->pong = ((char*)msg->data)[0];
            break;
        case WINDD_MSG_TYPE_INPUT_EVENT:
            if(msg->datalen != sizeof(struct input_event)) {
                res = -EINVAL;
                break;
            }
            res = windd_window_on_recv_input_msg(
                    win,
                    (struct input_event*)msg->data);
            break;
        default:
            res = -EINVAL;
            break;
    }
    return res;
}

int windd_window_poll(struct window *win)
{
    int res;

    windd_window_lock_read(win);

    if(win->partial_msg == NULL) {
        struct window_msg msg_hdr;
        ssize_t hdramt = read(win->conn, &msg_hdr, sizeof(struct window_msg));
        if(hdramt < 0) {
            if(hdramt == -EWOULDBLOCK) {
                windd_window_unlock_read(win);
                return 0;
            }
            return hdramt;
        } else if(hdramt == 0) {
            win->disconnected = 1;
            windd_window_unlock_read(win);
            return 0;
        }

        struct window_msg *msg =
            malloc(msg_hdr.datalen + sizeof(struct window_msg));
        if(msg == NULL) {
            windd_window_unlock_read(win);
            return -ENOMEM;
        }

        memcpy(msg, &msg_hdr, sizeof(struct window_msg));
        win->partial_msg = msg;
    } else {
        //printf("windd_window: partial read!\n");
    }

    struct window_msg *msg = win->partial_msg;
    if(msg->datalen > 0) {
        ssize_t dataamt = read(win->conn, &msg->data, msg->datalen);
        if(dataamt < 0) {
            if(dataamt == -EWOULDBLOCK) {
                // Leave the partial_msg in "win->partial_msg"
                windd_window_unlock_read(win);
                return 0;
            }
            return dataamt;
        } else if(dataamt == 0) {
            win->partial_msg = NULL;
            free(msg);
            win->disconnected = 1;
            windd_window_unlock_read(win);
            return 0;
        }
    }

    win->partial_msg = NULL;
    windd_window_unlock_read(win);
    res = windd_window_on_recv_msg(win, msg);
    free(msg);
    return res;
}

int windd_window_reload_buffer(
        struct window *win)
{
    int res;
    windd_window_lock_buffer(win);

    if(!win->layout_valid) {
        windd_window_unlock_buffer(win);
        return 0;
    }

    size_t req_len = win->layout.offset + (win->layout.width * win->layout.height) * win->layout.stride;

    // Round up to the nearest page...
    req_len += 0xFFF;
    req_len &= ~0xFFF;

    if(req_len == win->buffer_size) {
        windd_window_unlock_buffer(win);
        return 0;
    }
    //printf("windd_window_reload_buffer: need to remap buffer (req=0x%lx, cur=0x%lx) buffer=%p\n",
    //        (unsigned long)req_len,
    //        (unsigned long)win->buffer_size,
    //        win->buffer);

    if(win->buffer_size > 0) {
        kanawha_sys_munmap(win->buffer);
    }
    win->buffer = NULL;
    win->buffer_size = 0;

    //printf("windd_window_reload_buffer: mapping 0x%lx bytes!\n",
    //        (unsigned long)req_len);
    res = kanawha_sys_mmap(
            win->conn,
            0,
            &win->buffer,
            req_len,
            MMAP_SHARED|MMAP_PROT_READ|MMAP_PROT_WRITE);
    if(res) {
        windd_window_unlock_buffer(win);
        return res;
    }

    win->buffer_size = req_len;

    windd_window_unlock_buffer(win);
    return 0;
}

int windd_window_ping(struct window *win)
{
    struct window_msg msg = {
        .type = WINDD_MSG_TYPE_PING,
        .datalen = 1,
    };

    win->pong = '\0';
    windd_window_lock_write(win);
    write(win->conn, &msg, sizeof(msg));
    char ping = '0';
    write(win->conn, &ping, 1);
    windd_window_unlock_write(win);

    while(win->pong != '1') {
        windd_window_poll(win);
    }

    return 0;
}

int windd_window_server_set_layout(struct window *win, struct gfx_layout *layout)
{
    if(win->mode != WINDOW_MODE_SERVER) {
        return -EINVAL;
    }
    win->layout_valid = 1;
    win->layout = *layout;

    windd_window_reload_buffer(win);

    return windd_server_window_notify_layout(win);
}
int windd_window_server_set_position(struct window *win, struct window_position *pos)
{
    if(win->mode != WINDOW_MODE_SERVER) {
        return -EINVAL;
    }
    win->position_valid = 1;
    win->position = *pos;

    return windd_server_window_notify_position(win);
}

int windd_window_get_layout(struct window *win, struct gfx_layout *layout)
{
    int res;

    if(win->layout_valid) {
        *layout = win->layout;
        return 0;
    }

    { // Issue a request to the server
        struct window_msg msg = {
            .type = WINDD_MSG_TYPE_REQ_LAYOUT,
            .datalen = 0,
        };
        windd_window_lock_write(win);
        write(win->conn, &msg, sizeof(msg));
        windd_window_unlock_write(win);
    }

    while(!win->layout_valid) {
        res = windd_window_poll(win);
        if(res) {
            return res;
        }
        if(windd_window_disconnected(win)) {
            return -EINVAL;
        }
    }

    *layout = win->layout;
    return 0;
}

int windd_window_get_position(struct window *win, struct window_position *pos)
{
    int res;

    if(win->position_valid) {
        *pos = win->position;
        return 0;
    }

    { // Issue a request to the server
        struct window_msg msg = {
            .type = WINDD_MSG_TYPE_REQ_POSITION,
            .datalen = 0,
        };
        windd_window_lock_write(win);
        write(win->conn, &msg, sizeof(msg));
        windd_window_unlock_write(win);
    }

    while(!win->position_valid) {
        res = windd_window_poll(win);
        if(res) {
            return res;
        }
        if(windd_window_disconnected(win)) {
            return -EINVAL;
        }
    }

    *pos = win->position;
    return 0;
}

static int
windd_input_lock_acquire(
        struct window *win)
{
    while(__atomic_fetch_or(&win->input_lock, 1, __ATOMIC_SEQ_CST)) {}
}

static int
windd_input_lock_release(
        struct window *win)
{
    __atomic_fetch_and(&win->input_lock, 0, __ATOMIC_SEQ_CST);
}

int windd_window_send_input(struct window *win, struct input_event *evt)
{
    windd_input_lock_acquire(win);
    struct window_msg msg = {
        .type = WINDD_MSG_TYPE_INPUT_EVENT,
        .datalen = sizeof(struct input_event),
    };
    windd_window_lock_write(win);
    write(win->conn, &msg, sizeof(msg));
    write(win->conn, evt, sizeof(struct input_event));
    windd_window_unlock_write(win);
    windd_input_lock_release(win);
    return 0;
}
static int windd_window_on_recv_input_msg(
        struct window *win,
        struct input_event *evt)
{
    windd_input_lock_acquire(win);
    if(win->input_buflen <= 0) {
        windd_input_lock_release(win);
        return -ENOMEM;
    }
    if(((win->input_head+1) % win->input_buflen) == win->input_tail) {
        // Buffer is full
        // Drop the least recently received
        // input event...
        win->input_tail++;
        win->input_tail = win->input_tail % win->input_buflen;
    }
    win->input_ringbuf[win->input_head] = *evt;
    win->input_head++;
    win->input_head = win->input_head % win->input_buflen;
    windd_input_lock_release(win);
    return 0;
}
int windd_window_recv_input(struct window *win, struct input_event *evt)
{
    windd_input_lock_acquire(win);
    if(win->input_buflen <= 0) {
        windd_input_lock_release(win);
        return -ENXIO;
    }
    if(win->input_tail == win->input_head) {
        windd_input_lock_release(win);
        return -ENXIO;
    }
    // Pop off an event
    *evt = win->input_ringbuf[win->input_tail];
    win->input_tail++;
    win->input_tail = win->input_tail % win->input_buflen;
    windd_input_lock_release(win);
    return 0;
}
int windd_window_set_input_buflen(struct window *win, unsigned long len)
{
    windd_input_lock_acquire(win);
    if(win->input_buflen == len) {
        windd_input_lock_release(win);
        return 0;
    }

    if(win->input_buflen > 0) {
        free(win->input_ringbuf);
    }

    win->input_head = 0;
    win->input_tail = 0;
    win->input_buflen = len;
    win->input_ringbuf = malloc(sizeof(struct input_event) * win->input_buflen);
    if(win->input_ringbuf == NULL) {
        win->input_buflen = 0;
        windd_input_lock_release(win);
        return -ENOMEM;
    }

    windd_input_lock_release(win);
    return 0;
}


int windd_window_disconnected(struct window *window)
{
    int res;
    if(window->disconnected) {
        return 1;
    }
    unsigned long value;
    res = kanawha_sys_fattr(window->conn, FILE_ATTR_CONNECTED, &value);
    if(res) {
        return res;
    }
    return !value;
}

