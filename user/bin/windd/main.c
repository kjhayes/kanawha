
#include <windd/windd.h>
#include <errno.h>
#include <kanawha/sys-wrappers.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <threads.h>
#include <string.h>
#include <sys/mman.h>

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

//        printf("windd: waiting for connection...\n");
        struct window *win = windd_server_await_connection();
        if(win == NULL) {
            continue;
        }

        thrd_t child;
        res = thrd_create(&child, window_main, win);
        if(res) {
            fprintf(stderr, "windd: Failed to create child thread for window!\n");
            windd_server_close_connection(win);
            continue;
        }
//        printf("windd: finished creating window thread...\n");
    }

    windd_server_deinit();

    return 0;
}

static int
window_main(void *_win)
{
    int res;
    struct window *win = _win;

    printf("windd: opened window thread...\n");

    void *buffer;
    res = kanawha_sys_mmap(
            win->conn,
            0,
            &buffer,
            0x1000,
            MMAP_SHARED|MMAP_PROT_READ|MMAP_PROT_WRITE);
    if(res) {
        fprintf(stderr, "Failed to map window connection buffer!\n");
        windd_server_close_connection(win);
        return -1;
    }

    strcpy((char*)buffer, "Hello World!");

    while(1)
    {
        if(windd_window_disconnected(win)) {
            break;
        }
    }

    printf("windd: closing window thread...\n");
    windd_server_close_connection(win);

    return 0;
}

