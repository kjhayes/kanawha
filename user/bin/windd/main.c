
#include <windd/windd.h>
#include <errno.h>
#include <kanawha/sys-wrappers.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static int window_main(struct window *window);

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

        do
        {
            res = waitpid(-1, NULL, WNOHANG);
        } while(res > 0);

        if(res < 0)
        {
            fprintf(stderr, "windd: Failed to wait for children!\n");
        }

        struct window *win = windd_server_await_connection();
        if(win == NULL) {
            continue;
        }

        int child = fork();

        if(child == 0)
        {
            res = window_main(win);
            windd_server_close_connection(win);
            return res;
        }
        else
        {
            windd_server_close_connection(win);
        }
    }

    windd_server_deinit();

    return 0;
}

static int
window_main(struct window *win)
{
    int res;
    while(1)
    {
        // Handle requests for this window
        // TODO
    }
}

