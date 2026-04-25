
#include <lens/internal.h>
#include <lens/lens.h>
#include <lens/server.h>
#include <lens/gfx.h>
#include <sock/sock.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

static int
lens_server_on_recv(
        struct sock_connection *conn,
        struct sock_msg *msg,
        void *state)
{
    struct lens_client *client =
        container_of(conn, struct lens_client, conn);

    switch(msg->type) {
        case LENS_MSG_FLUSH_REQ:
            client->flush_req = 1;
            return 0;
        case LENS_MSG_QUERY_GFX_INFO:
            client->gfx_info_desync = 1;
            return lens_client_sync_gfx_info(client);
        default:
            fprintf(stderr, "lens_server_on_recv: unrecognized message type %d!\n",
                    (int)msg->type);
            return -EINVAL;
    }
}

struct lens_client *
lens_server_wait_for_client(void)
{
    int res;

    struct lens_client *client;
    client = malloc(sizeof(*client));
    if(client == NULL) {
        return NULL;
    }

    client->flush_req = 0;

    sem_init(&client->gfx_lock,1,1);
    client->gfx_info_desync = 1;
    client->gfx_info = NULL;
    client->gfx_frame = NULL;

    res = sock_open_server_connection(
            __lens_socket,
            &client->conn);
    if(res) {
        free(client);
        return NULL;
    }

    return client;
}

int
lens_server_close_client(
        struct lens_client *client)
{
    sem_destroy(&client->gfx_lock);
    if(client->gfx_info) {
        if(client->gfx_info->frame_size > 0) {
            sock_connection_unmap_shmem(
                    &client->conn,
                    0,
                    client->gfx_info->frame_size,
                    client->gfx_frame);
        }
        free(client->gfx_info);
        client->gfx_frame = 0;
        client->gfx_info_desync = 0;
    }
    sock_close_server_connection(&client->conn);
    free(client);
    return 0;
}

int
lens_server_poll_client(
        struct lens_client *client)
{
    return sock_connection_poll(
            &client->conn,
            lens_server_on_recv,
            NULL);
}

int
lens_client_requested_flush(
        struct lens_client *client)
{
    return client->flush_req;
}
int
lens_client_ack_flush(
        struct lens_client *client)
{
    int res;
    if(!client->flush_req) {
        return 0;
    }

    res = sock_connection_send_msg(
            &client->conn,
            LENS_MSG_FLUSH_ACK,
            0,
            NULL,
            0);

    if(res) {
        return res;
    }

    client->flush_req = 0;
}

static struct lens_gfx_info
default_gfx_info = {
    .num_layers = 0,
    .frame_size = 0,
};

int
lens_client_sync_gfx_info(
        struct lens_client *client)
{
    int res;
    while(sem_wait(&client->gfx_lock)) {}

    if(!client->gfx_info_desync) {
        fprintf(stderr, "lens_client: sync requested when no desync is detected!\n");
        sem_post(&client->gfx_lock);
        return 0;
    }

    size_t len;
    struct lens_gfx_info *info;

    if(client->gfx_info != NULL) {
        len = sizeof(*client->gfx_info)
            +(sizeof(client->gfx_info->layer_layout[0]) * client->gfx_info->num_layers);
        info = client->gfx_info;
    } else {
        len = sizeof(default_gfx_info);
        info = &default_gfx_info;
    }

    res = sock_connection_send_msg(
            &client->conn,
            LENS_MSG_NOTIFY_GFX_INFO,
            0,
            (void*)info,
            len);
    if(res) {
        fprintf(stderr, "lens_client: failed to send NOTIFY_GFX message!\n");
        sem_post(&client->gfx_lock);
        return res;
    }

    client->gfx_info_desync = 0;

    sem_post(&client->gfx_lock);
    return 0;
}

int
lens_client_send_input_event(
        struct lens_client *client,
        struct input_event *evt)
{
    return sock_connection_send_msg(
            &client->conn,
            LENS_MSG_INPUT_EVT,
            0,
            evt,
            sizeof(*evt));
}

int
lens_client_set_gfx_info(
        struct lens_client *client,
        struct lens_gfx_info *info)
{
    int res;
    while(sem_wait(&client->gfx_lock)) {}

    if(client->gfx_info) {
        if(client->gfx_info->frame_size > 0) {
            sock_connection_unmap_shmem(
                    &client->conn,
                    0,
                    client->gfx_info->frame_size,
                    client->gfx_frame);
        }
        free(client->gfx_info);
        client->gfx_info = NULL;
        client->gfx_frame = NULL;
        client->gfx_info_desync = 1;
    }

    size_t info_len = sizeof(struct lens_gfx_info)
                   + (sizeof(info->layer_layout[0]) * info->num_layers);

    struct lens_gfx_info *new = malloc(info_len);
    if(new == NULL) {
        sem_post(&client->gfx_lock);
        return -ENOMEM;
    }

    memcpy(new, info, info_len);

    if(info->frame_size > 0) {
        res = sock_connection_map_shmem(
                &client->conn,
                0,
                info->frame_size,
                &client->gfx_frame);
        if(res) {
            free(info);
            sem_post(&client->gfx_lock);
            return res;
        }
    }
    client->gfx_info = info;
    client->gfx_info_desync = 1;

    sem_post(&client->gfx_lock);
    return 0;
}

int
lens_client_lock_gfx(
        struct lens_client *client)
{
    while(sem_wait(&client->gfx_lock)) {}
    return 0;
}
int
lens_client_unlock_gfx(
        struct lens_client *client)
{
    sem_post(&client->gfx_lock);
    return 0;
}

static struct lens_gfx_info
default_lens_client_gfx_info = {
    .num_layers = 0,
    .frame_size = 0,
};

struct lens_gfx_info *
lens_client_get_gfx_info(
        struct lens_client *client)
{
    if(client->gfx_info == NULL) {
        return &default_lens_client_gfx_info;
    } else {
        return client->gfx_info;
    }
}

void *
lens_client_get_gfx_frame(
        struct lens_client *client)
{
    return client->gfx_frame;
}

