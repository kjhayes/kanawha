
#include <errno.h>
#include <stdio.h>
#include <string.h>

void
perror(const char *s)
{
    if(s) {
        fprintf(stderr, s);
        fprintf(stderr, ": ");
    }

    fprintf(stderr, "%s\n", strerror(errno));
}

