
#include <bark/bark.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

int main(int argc,
         const char **argv)
{
    int res;
    res = bark_init();
    if(res) {
        fprintf(stderr, "beep: failed to initialize bark!\n");
        return res;
    }

    struct bark_stream *stream;
    stream = bark_stream_open();
    if(stream == NULL) {
        fprintf(stderr, "beep: failed to open bark stream!\n");
        bark_deinit();
        return -ENXIO;
    }

    res = bark_stream_beep(stream);
    if(res) {
        fprintf(stderr, "bark_stream_beep: returned %d!\n", res);
        return res;
    }

    // If we just return immediately
    // we will close the connection before
    // the bark daemon sees our request
    // (technically we have a race condition
    //  here either way...)
    sleep(1);

    bark_stream_close(stream);
    bark_deinit();
    return 0;
}

