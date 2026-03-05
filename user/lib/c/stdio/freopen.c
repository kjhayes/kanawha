
#include <elk-libc-internal/__sFILE.h>
#include <elk-libc-internal/dofopen.h>
#include <stdio.h>

FILE *
freopen(const char *restrict filename,
        const char *restrict mode,
        FILE *restrict stream)
{
    int res;

    if(filename == NULL)
    {
        // TODO support changing the mode of a file
        fclose(stream);
        errno = -EUNIMPL;
        return NULL;
    }
    else
    {
        fflush(stream);
        kanawha_sys_close(stream->__fd);

        __elk_libc_internal__deinit_sFILE(stream);
        __elk_libc_internal__init_sFILE(stream);

        res = __elk_libc_internal__dofopen(filename, mode, stream);
        if(res)
        {
            free(stream);
            errno = res;
            return NULL;
        }

        return stream;
    }
}
