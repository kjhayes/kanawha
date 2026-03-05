
#include <stdio.h>
#include <stdlib.h>

_Noreturn void
abort(void)
{
    fprintf(stderr, "abort()\n");
    exit(EXIT_FAILURE);
}
