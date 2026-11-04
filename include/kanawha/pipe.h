#ifndef __KANAWHA__PIPE_H__
#define __KANAWHA__PIPE_H__

#include <kanawha/fs/node.h>

struct fs_node *
pipe_create_pipe_anonymous(void);

struct fs_node *
pipe_create_mux_anonymous(void);

#endif
