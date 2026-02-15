
#include <stdio.h>
#include "elk-libc-internal/FILE.h"
#include "elk-libc-internal/__sFILE.h"

struct __sFILE __ELK_stdin = {
    .__fd = 0,
};

struct __sFILE __ELK_stdout = {
    .__fd = 1,
};

struct __sFILE __ELK_stderr = {
    .__fd = 2,
};

int
__elk_crt__init_stdstreams(void)
{
    // We assume we inherited a file table
    // with stdin, stdout and stderr open on
    // descriptors 0, 1, and 2 respectively

    __elk_libc_internal__init_sFILE(&__ELK_stdin);
    __elk_libc_internal__init_sFILE(&__ELK_stdout);
    __elk_libc_internal__init_sFILE(&__ELK_stderr);

    __ELK_stdin.__fd = 0;
    __ELK_stdout.__fd = 1;
    __ELK_stderr.__fd = 2;

    stdin  = (FILE *)&__ELK_stdin;
    stdout = (FILE *)&__ELK_stdout;
    stderr = (FILE *)&__ELK_stderr;

    return 0;
}

