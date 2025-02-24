
#include <stdlib.h>
#include <stdio.h>

_Noreturn void abort(void)
{
    fprintf(stderr, "abort()\n");
    exit(EXIT_FAILURE);
}

