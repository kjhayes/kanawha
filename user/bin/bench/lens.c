
#include "log.h"
#include <lens/lens.h>
#include <lens/window.h>
#include <errno.h>
#include <unistd.h>

int
lens_main(int argc, const char **argv)
{
    int res;
    res = lens_init();
    if(res) {
        ERROR("Failed to initialize windowing library!\n");
        return res;
    }

    struct lens_window *win;
    win = lens_open_window();
    if(win == NULL) {
        ERROR("Failed to open a window!\n");
        return -EINVAL;
    }

    res = lens_close_window(win);
    if(res) {
        ERROR("Failed to close window!\n");
        return res;
    }

    res = lens_deinit();
    if(res) {
        ERROR("Failed to cleanup windowing library!\n");
        return res;
    }

    return 0;
}

