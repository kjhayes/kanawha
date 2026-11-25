
#include <lens/window.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include <sock/socket.h>
#include <sock/conn.h>

extern struct sock_socket *lens_socket;

struct lens_window {
    struct sock_conn *conn;
};

struct lens_window *
lens_open_window(void)
{
    if(lens_socket == NULL) {
        return NULL;
    }

    struct lens_window *window;
    window = malloc(sizeof(*window));
    if(window == NULL) {
        return NULL;
    }

    window->conn = sock_connect(lens_socket);
    if(window->conn == NULL) {
        free(window);
        return NULL;
    }

    return window;
}

int
lens_close_window(
        struct lens_window *window)
{
    sock_close_conn(window->conn);
    free(window);
    return 0;
}

