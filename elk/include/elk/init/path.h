#ifndef __KANAWHA__ELK_INIT_H__
#define __KANAWHA__ELK_INIT_H__

#include <kanawha/uapi/file.h>

fd_t
open_path(
        const char *path,
        unsigned long perm_flags,
        unsigned long mode_flags);


#endif
