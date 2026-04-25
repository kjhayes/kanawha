#ifndef __KANAWHA__BARK_BARK_H__
#define __KANAWHA__BARK_BARK_H__

int
bark_init(void);
int
bark_deinit(void);

struct bark_stream;
struct bark_client;

// Client side API
struct bark_stream *
bark_stream_open(void);
int
bark_stream_close(
        struct bark_stream *stream);

int
bark_stream_beep(struct bark_stream *stream);

// Server side API
struct bark_client *
bark_server_wait_for_client(void *priv);
int
bark_server_close_client(
        struct bark_client *client);

int
bark_client_poll(
        struct bark_client *client);

#endif
