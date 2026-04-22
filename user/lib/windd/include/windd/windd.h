#ifndef __KANAWHA__ELK__WINDD_H__
#define __KANAWHA__ELK__WINDD_H__

#include <kanawha/gfx.h>
#include <kanawha/input.h>
#include <stdint.h>

struct window_msg
{
#define WINDD_MSG_TYPE_SET_LAYOUT (1)
#define WINDD_MSG_TYPE_SET_POSITION (2)
#define WINDD_MSG_TYPE_REQ_LAYOUT (3)
#define WINDD_MSG_TYPE_REQ_POSITION (4)
#define WINDD_MSG_TYPE_INPUT_EVENT (5)
#define WINDD_MSG_TYPE_PING (100)
#define WINDD_MSG_TYPE_PONG (101)
    uint32_t type;
    uint32_t datalen;
    char data[];
};

struct window_position
{
    uint32_t x;
    uint32_t y;
};

struct window
{
    int conn;
    unsigned mode : 1;
    unsigned disconnected : 1;

    int buffer_lock;
    unsigned long buffer_size;
    void *buffer;

    unsigned layout_valid : 1;
    struct gfx_layout layout;

    unsigned position_valid : 1;
    struct window_position position;

    char pong;

    int write_lock;
    int read_lock;
    struct window_msg *partial_msg;

    int input_lock;
    unsigned long input_buflen;
    unsigned long input_head;
    unsigned long input_tail;
    struct input_event *input_ringbuf;
};

int
windd_client_init(void);
int
windd_client_deinit(void);

int
windd_server_init(void);
int
windd_server_deinit(void);

int
windd_window_lock_read(struct window *win);
int
windd_window_unlock_read(struct window *win);
int
windd_window_lock_write(struct window *win);
int
windd_window_unlock_write(struct window *win);

int
windd_window_lock_buffer(struct window *win);
int
windd_window_unlock_buffer(struct window *win);

int
windd_window_reload_buffer(struct window *win);

struct window *
windd_server_await_connection(void);
int
windd_server_close_connection(struct window *window);

struct window *
windd_client_open(void);
int
windd_client_close(struct window *window);

int
windd_window_poll(struct window *win);
int
windd_window_ping(struct window *win);

int
windd_window_send_input(struct window *win, struct input_event *evt);
int
windd_window_recv_input(struct window *win, struct input_event *evt);
int
windd_window_set_input_buflen(struct window *win, unsigned long len);

int
windd_window_server_set_layout(struct window *win, struct gfx_layout *layout);
int
windd_window_server_set_position(struct window *win,
                                 struct window_position *pos);

int
windd_window_get_layout(struct window *win, struct gfx_layout *layout);
int
windd_window_get_position(struct window *win, struct window_position *pos);

int
windd_window_disconnected(struct window *win);

#endif
