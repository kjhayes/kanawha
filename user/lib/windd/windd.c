
#include <windd/windd.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <kanawha/sys-wrappers.h>

#define WINDOW_MODE_CLIENT (0U)
#define WINDOW_MODE_SERVER (1U)

struct window {
    int conn;
    unsigned mode : 1;
};

static int windd_inited = 0;
static int windd_socket = -1;

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
    return window;
}

int
windd_server_close_connection(struct window *window)
{
    kanawha_sys_close(window->conn);
    free(window);
    return 0;
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
    return window;
}

int windd_client_close(struct window *window)
{
    kanawha_sys_close(window->conn);
    free(window);
    return 0;
}

