
#include <windd/windd.h>
#include <errno.h>
#include <kanawha/sys-wrappers.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <threads.h>

static int window_main(void *window);

int
main(int argc, const char **argv)
{
    int res;

    res = windd_server_init();
    if(res) {
        fprintf(stderr, "windd: Failed to initialize server!\n");
        return res;
    }

    int running = 1;
    while(running)
    {
        res = waitpid(-1, NULL, WNOHANG);
        if(res < 0 && res != -EWOULDBLOCK)
        {
            fprintf(stderr, "windd: Failed to wait for children!\n");
        }

        printf("windd: waiting for connection...\n");
        struct window *win = windd_server_await_connection();
        if(win == NULL) {
            continue;
        }

        thrd_t child;
        res = thrd_create(&child, window_main, win);
        if(res) {
            windd_server_close_connection(win);
            fprintf(stderr, "windd: Failed to create child thread for window!\n");
            continue;
        }
    }

    windd_server_deinit();

    return 0;
}

static int
window_main(void *_win)
{
    struct window *win = _win;

    printf("windd: opened server window thread...\n");

    int res;
    while(1)
    {
        // Handle requests for this window
        // TODO

        if(windd_window_disconnected(win)) {
            break;
        }
    }

    printf("windd: closing server window thread...\n");
    return 0;
}

