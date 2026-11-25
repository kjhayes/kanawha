#ifndef __KANAWHA__LENS_SERVER_H__
#define __KANAWHA__LENS_SERVER_H__

struct lens_client;

struct lens_client *
lens_accept_client(void);
int
lens_close_client(
        struct lens_client *client);

#endif
