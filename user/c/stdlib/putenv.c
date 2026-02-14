
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int putenv(char *string)
{
    char *eq = strchr(string, '=');
    if(eq == NULL) {
        errno = -EINVAL;
        return -1;
    }

    char *name = string;
    char *val = eq+1;
    *eq = '\0';

    return setenv(name, val, 1);
}

