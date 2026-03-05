
#include <elk-libc-internal/__sFILE.h>
#include <stdio.h>
#include <stdio_ext.h>

void
__fpurge(FILE *file)
{
    int res;
    res = __elk_libc_internal__file_purge(file);
    errno = res;
}
