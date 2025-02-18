
#include <elk-libc-internal/__sFILE.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/file.h>

#include <stdio.h>
#include <string.h>
#include <assert.h>

#undef fgetc
int fgetc(FILE *stream)
{
    ssize_t res;
    struct __sFILE *file = (struct __sFILE *)stream;

    assert(file != NULL);

    char c;

    res = kanawha_sys_read(
            file->__fd,
            &c,
            sizeof(char));
    if(res != 1) {
        // TODO set FILE error
        return EOF;
    }

    return c;
}

