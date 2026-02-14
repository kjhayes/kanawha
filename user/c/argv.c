
#include <elk-libc-internal/argv.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/environ.h>

int
__elk_libc__set_argv(
        int argc,
        char **argv)
{
    int res;

    size_t len = 0;
    for(int i = 0; i < argc; i++) {
        len += strlen(argv[i]) + 1;
    }

    char *buffer = malloc(len);
    if(buffer == NULL) {
        return -ENOMEM;
    }

    char *iter = buffer;
    memset(buffer, 0, len);
    for(int i = 0; i < argc; i++) {
        char *str = argv[i];
        size_t curlen = strlen(str);
        memcpy(iter, str, curlen);
        iter += curlen;
        if(i < argc-1) {
            *iter = ' ';
            iter++;
        } else {
            *iter = '\0';
            break;
        }
    }

    res = kanawha_sys_environ(
            "ARGV",
            buffer,
            len,
            ENV_SET);
    if(res) {
        free(buffer);
        return res;
    }
    free(buffer);

    return 0;
}

