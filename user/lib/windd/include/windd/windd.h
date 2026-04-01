#ifndef __KANAWHA__ELK__WINDD_H__
#define __KANAWHA__ELK__WINDD_H__

struct window {
    int conn;
    unsigned mode : 1;
};

int windd_client_init(void);
int windd_client_deinit(void);

int windd_server_init(void);
int windd_server_deinit(void);

struct window *windd_server_await_connection(void);
int windd_server_close_connection(struct window *window);

struct window *windd_client_open(void);
int windd_client_close(struct window *window);

int windd_window_disconnected(struct window *win);

#endif
