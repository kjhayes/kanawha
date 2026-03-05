
#include <stdio.h>
#include <stdio_ext.h>

size_t
__fpending(FILE *file)
{
    // We do not buffer output on files
    return 0;
}
