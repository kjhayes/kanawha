
#include <stdlib.h>
#include <stdio.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/environ.h>

#define GETENV_MAXLEN 1024
static char __getenv_buffer[GETENV_MAXLEN] = {0};

char *getenv(const char *name)
{
    int res;
    res = kanawha_sys_environ(
            name,
            __getenv_buffer,
            GETENV_MAXLEN,
            ENV_GET);
    if(res) {
        // TODO set errno (technically not supposed to be allowed to fail)
        return NULL;
    }

    __getenv_buffer[GETENV_MAXLEN-1] = '\0';

    return __getenv_buffer;
}

