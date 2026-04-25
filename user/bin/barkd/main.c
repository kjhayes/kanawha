
#include <bark/bark.h>
#include <stdio.h>
#include <unistd.h>
#include <threads.h>

static int
client_thread(void *_client)
{
    struct bark_client *client = _client;

    int res;

    int running = 1;
    while(running) {
        res = bark_client_poll(client);
        if(res) {
            break;
        }
    }

    bark_server_close_client(client);
    return res;
}

int main(int argc, const char **argv)
{
    int res;

    res = bark_init();
    if(res) {
        fprintf(stderr, "barkd: failed to start libbark!\n");
        return res;
    }

    int running = 1;
    while(running) {
        struct bark_client *client;
        client = bark_server_wait_for_client(NULL);
        if(client == NULL) {
            fprintf(stderr, "barkd: failed to wait for client!\n");
            continue;
        }

        thrd_t id;
        res = thrd_create(&id, client_thread, (void*)client);
        if(res) {
            fprintf(stderr, "barkd: failed to create client thread! (err=%d)\n",
                    res);
            continue;
        }
    }
}

