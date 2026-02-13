
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

int symlink(const char *path1, const char *path2)
{
    fprintf(stderr, "Attempted to create symlink between \"%s\" and \"%s\"!\n",
            path1, path2);
    errno = -EUNIMPL;
    return -1;
}

