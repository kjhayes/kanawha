
#include <threads.h>
#include <stdio.h>
#include "lensd.h"

static thrd_t listener;

static int
listener_thread(void *_state)
{
    int res;

    while(lensd_running)
    {
        struct lens_client *client;
        client = lens_server_wait_for_client();
        if(client == NULL) {
            fprintf(stderr, "lensd: failed to wait for client!\n");
            continue;
        }

        res = add_lens_client(client);
        if(res) {
            lens_server_close_client(client);
            fprintf(stderr, "lensd: failed to push new client!\n");
            continue;
        }
    }

    return 0;
}

int
listener_init(void)
{
    int res;

    res = thrd_create(&listener, listener_thread, NULL);
    if(res) {
        fprintf(stderr, "lensd: failed to start new window listener thread!\n");
        return res;
    }

    return 0;
}

int
listener_deinit(void)
{
    int res;
    int exitcode;
    res = thrd_join(listener, &exitcode);
    if(res) {
        return res;
    }
    return exitcode;
}

