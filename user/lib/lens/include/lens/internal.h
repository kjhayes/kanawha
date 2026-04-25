#ifndef __KANAWHA__LENS_INTERNAL_H__
#define __KANAWHA__LENS_INTERNAL_H__

#include <lens/lens.h>
#include <lens/window.h>
#include <lens/input_buffer.h>
#include <sock/connection.h>

enum {
    _LENS_MSG_BASE = -1,

    LENS_MSG_FLUSH_REQ, // client -> server
    LENS_MSG_FLUSH_ACK, // server -> client

    LENS_MSG_QUERY_GFX_INFO,  // client -> server
    LENS_MSG_NOTIFY_GFX_INFO, // server -> client
 
    LENS_MSG_INPUT_EVT, // server -> client
   
    _LENS_NUM_MSG_TYPES
};
_Static_assert(_LENS_NUM_MSG_TYPES <= SOCK_MSG_ID_LIMIT,
        "liblens: number of message types is greater than SOCK_MSG_ID_LIMIT!");

struct lens_window {
    struct sock_connection conn;
    unsigned int gfx_info_req : 1;

    unsigned long flush_req_count;

    sem_t gfx_lock;
    struct lens_gfx_info *gfx_info;
    void *gfx_frame;

    struct lens_input_buffer *input_buffer;
};

struct lens_client {
    struct sock_connection conn;
    unsigned int flush_req : 1;

    sem_t gfx_lock;
    unsigned int gfx_info_desync : 1;
    struct lens_gfx_info *gfx_info;
    void *gfx_frame;
};

extern struct sock_socket *__lens_socket;

#endif
