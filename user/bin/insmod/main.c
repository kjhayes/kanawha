
#include <stdio.h>
#include "kanawha/sys-wrappers.h"

const char *progname = "insmod";

int main(int argc, const char **argv)
{
    int res;

    if(argc > 0) {
        progname = argv[0];
    }

    if(argc != 3) {
        fprintf(stderr, "Usage: %s [FILE] [MODNAME]\n");
        return -1;
    }

    const char *path = argv[1];
    const char *modname = argv[2];

    fd_t fd;
    res = kanawha_sys_open(
            path,
            FILE_PERM_READ,
            0,
            &fd);
    if(res) {
        fprintf(stderr, "Failed to open file \"%s\"\n", path);
        return -1;
    }

    res = kanawha_sys_insmod(
            fd,
            modname,
            0);
    if(res) {
        fprintf(stderr, "Failed to insert module \"%s\"\n", modname);
        return -1;
    }

    kanawha_sys_close(fd);

    return 0;
}

