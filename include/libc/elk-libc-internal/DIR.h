#ifndef __ELK_LIBC_INTERNAL__DIR_H__
#define __ELK_LIBC_INTERNAL__DIR_H__

#include <kanawha/file.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>

struct DIR
{
    fd_t fd;
    struct dirent *dirent;

    unsigned eod : 1;
};

static inline DIR *
__elk_libc_internal__alloc_DIR(void)
{
    DIR *dir = malloc(sizeof(*dir));
    if(dir == NULL) {
        return NULL;
    }

    dir->fd = 0;
    dir->dirent = NULL;
    dir->eod = 0;
    return dir;
}

static inline void
__elk_libc_internal__free_DIR(
        DIR *dir)
{
    free(dir->dirent);
    free(dir);
}

#endif
