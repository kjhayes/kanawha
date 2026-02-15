
#include <sys/stat.h>

int lstat(
        const char *restrict path,
        struct stat *restrict buffer)
{
    // TODO this is incorrect,
    // we need to handle the case that "path"
    // is a symlink.
    return stat(path, buffer);
}

