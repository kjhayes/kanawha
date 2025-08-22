#ifndef __ELK_LIBC_INTERNAL__EXEC_PATH_H__
#define __ELK_LIBC_INTERNAL__EXEC_PATH_H__

#include <kanawha/file.h>

int
__elk_libc__exec_path_open(
        const char *file_name,
        fd_t *file_out);

int
__elk_libc__exec_path_lookup(
        const char *file_name,
        fd_t *file_out);

#endif
