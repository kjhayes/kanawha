#ifndef __KANAWHA__LENS_SERVER_H__
#define __KANAWHA__LENS_SERVER_H__

#include <kanawha/input.h>
#include <lens/gfx.h>

struct lens_client;

struct lens_client *
lens_server_wait_for_client(void);
int
lens_server_close_client(
        struct lens_client *client);

int
lens_server_poll_client(
        struct lens_client *client);

int
lens_client_requested_flush(
        struct lens_client *client);
int
lens_client_ack_flush(
        struct lens_client *client);

int
lens_client_send_input_event(
        struct lens_client *client,
        struct input_event *evt);

int
lens_client_set_gfx_info(
        struct lens_client *client,
        struct lens_gfx_info *info);
int
lens_client_sync_gfx_info(
        struct lens_client *client);

int
lens_client_lock_gfx(
        struct lens_client *client);
int
lens_client_unlock_gfx(
        struct lens_client *client);

struct lens_gfx_info *
lens_client_get_gfx_info(
        struct lens_client *client);
void *
lens_client_get_gfx_frame(
        struct lens_client *client);

#endif
