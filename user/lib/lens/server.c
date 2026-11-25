
#include <lens/server.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include <sock/socket.h>
#include <sock/conn.h>

extern struct sock_socket *lens_socket;

struct lens_client {
    struct sock_conn *conn;
};

struct lens_client *
lens_accept_client(void)
{
    if(lens_socket == NULL) {
        return NULL;
    }

    struct lens_client *client;
    client = malloc(sizeof(*client));
    if(client == NULL) {
        return NULL;
    }

    client->conn = sock_accept(lens_socket);
    if(client->conn == NULL) {
        free(client);
        return NULL;
    }

    // Configuring the sock connection

    sock_conn_finalize_config(client->conn);

    return client;
}

int
lens_close_client(
        struct lens_client *client)
{
    sock_close_conn(client->conn);
    free(client);
    return 0;
}


