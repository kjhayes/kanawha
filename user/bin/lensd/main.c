#include <lens/lens.h>
#include <lens/server.h>
#include <stdio.h>
#include <unistd.h>
#include <kanawha/syscall.h>

#include "display.h"
#include "input.h"
#include "util.h"

int lensd_running = 1;
int lensd_verbose = 1;

static const char *fb_dev_path = "/dev/fb/";
static const char *input_dev_path = "/dev/input/";

int main(int argc, const char **argv)
{
    int res;

    lensd_running = 1;

    lens_init(); 
    display_init();
    input_init();

    add_all_displays(fb_dev_path);
    add_all_inputs(input_dev_path);

    while(lensd_running) {
        struct lens_client *client;
        client = lens_accept_client();
        if(client == NULL) {
            ERROR("failed to accept client!\n");
            continue;
        }

        INFO("accepted client!\n");
    }

    input_deinit();
    display_deinit();
    lens_deinit();

    return 0;
}

