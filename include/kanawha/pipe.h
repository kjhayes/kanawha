#ifndef __KANAWHA__PIPE_H__
#define __KANAWHA__PIPE_H__

#include <kanawha/lock.h>
#include <kanawha/ptree.h>
#include <kanawha/waitqueue.h>

#include <kanawha/fs/node.h>

struct fs_node *
pipe_fs_get_anon_pipe(void);

#endif
