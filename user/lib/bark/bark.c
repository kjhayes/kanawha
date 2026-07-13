
#include <sock/sock.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

enum {
    BARK_MSG_BEEP = 0,
    
    _NUM_BARK_MSGS,
};

_Static_assert(_NUM_BARK_MSGS <= SOCK_MSG_ID_LIMIT,
        "Too many bark message types for current libsock limit!");

static struct sock_socket *barkd_socket = NULL;

int
bark_init(void) {
    barkd_socket = sock_open_socket("BARKD_SOCKET");
    if(barkd_socket == NULL) {
        return -ENXIO;
    }
    return 0;
}

int
bark_deinit(void) {
    int res;
    if(barkd_socket == NULL) {
        return -EINVAL;
    }
    res = sock_close_socket(barkd_socket);
    if(res) {
        return res;
    }
    return 0;
}

// Client side API
struct bark_stream {
    struct sock_connection conn;
};

static int
bark_stream_handle_msg(
        struct sock_connection *conn,
        struct sock_msg *msg,
        void *state)
{
    struct bark_stream *stream = container_of(conn, struct bark_stream, conn);
    switch(msg->type) {
        default:
            fprintf(stderr, "bark_stream: Ignoring unrecognized message type %d!\n",
                    (int)msg->type);
            break;
    }
    return 0;
}


struct bark_stream *
bark_stream_open(void)
{
    int res;

    struct bark_stream *stream = malloc(sizeof(*stream));
    if(stream == NULL) {
        return NULL;
    }

    res = sock_open_client_connection(
            barkd_socket,
            &stream->conn);
    if(res) {
        free(stream);
        return NULL;
    }

    return stream;
}
int
bark_stream_close(
        struct bark_stream *stream)
{
    int res;
    res = sock_close_client_connection(&stream->conn);
    if(res) {
        return res;
    }
    free(stream);
    return 0;
}

int
bark_stream_beep(
        struct bark_stream *stream)
{
    return sock_connection_send_msg(
            &stream->conn,
            BARK_MSG_BEEP,
            0,
            NULL,
            0);
}

// Server side API
struct bark_client {
    struct sock_connection conn;
};

static int
bark_server_handle_msg(
        struct sock_connection *conn,
        struct sock_msg *msg,
        void *state)
{
    struct bark_client *client = container_of(conn, struct bark_client, conn);
    switch(msg->type) {
        case BARK_MSG_BEEP:
            printf("BEEP!\n");
            break;
        default:
            fprintf(stderr, "bark_server: Ignoring unrecognized message type %d!\n",
                    (int)msg->type);
            break;
    }
    return 0;
}

struct bark_client *
bark_server_wait_for_client(void)
{
    int res;

    struct bark_client *client = malloc(sizeof(*client));
    if(client == NULL) {
        return NULL;
    }
    
    res = sock_open_server_connection(
            barkd_socket,
            &client->conn);
    if(res) {
        free(client);
        return NULL;
    }

    sock_connection_set_callback(&client->conn, bark_server_handle_msg, NULL);
    return client;
}
int
bark_server_close_client(
        struct bark_client *client)
{
    int res;
    res = sock_close_server_connection(&client->conn);
    if(res) {
        return res;
    }
    free(client);
    return 0;
}

int
bark_client_poll(
        struct bark_client *client)
{
    return sock_connection_poll(&client->conn);
}

