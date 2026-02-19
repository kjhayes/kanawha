#ifndef __KANAWHA__SOCKET_H__
#define __KANAWHA__SOCKET_H__

#include <kanawha/fs/node.h>

struct fs_node *
socket_create_anonymous(void);

struct fs_node *
pipe_create_anonymous(void);

#endif
