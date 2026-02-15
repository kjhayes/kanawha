
#include <stdio.h>
#include "kanawha/sys-wrappers.h"

const char *progname = "rmmod";

int main(int argc, const char **argv)
{
    int res;

    if(argc > 0) {
        progname = argv[0];
    }

    if(argc != 2) {
        fprintf(stderr, "Usage: %s [MODNAME]\n");
        return -1;
    }

    const char *modname = argv[1];

    res = kanawha_sys_rmmod(
            modname,
            0);
    if(res) {
        fprintf(stderr, "Failed to remove module \"%s\"\n", modname);
        return -1;
    }

    return 0;
}

