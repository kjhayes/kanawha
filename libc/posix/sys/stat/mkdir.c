
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <kanawha/sys-wrappers.h>

int
mkdir(const char *path, mode_t mode)
{
    int res;

    size_t pathlen = strlen(path);
    char *path_copy = malloc(pathlen+1);
    if(path_copy == NULL) {
        // TODO set errno
        return -1;
    }
    strncpy(path_copy, path, pathlen);
    path_copy[pathlen] = '\0';

    char *dirpath;
    char *filename = strrchr(path_copy, '/');
    if(filename == NULL) {
        dirpath = "";
        filename = path_copy;
    } else {
        dirpath = path_copy;
        filename[0] = '\0';
        filename = filename+1;
    }

    fd_t dir;
    res = kanawha_sys_open(
            dirpath,
            FILE_PERM_READ|FILE_PERM_WRITE,
            0,
            &dir);
    if(res) {
        free(path_copy);
        // TODO set errno
        return -1;
    }


    res = kanawha_sys_mkdir(
            dir,
            filename,
            0);
    if(res) {
        free(path_copy);
        kanawha_sys_close(dir);
        // TODO errno
        return -1;
    }
    free(path_copy);

    kanawha_sys_flush(dir, 0);
    kanawha_sys_close(dir);

    return 0;
}

