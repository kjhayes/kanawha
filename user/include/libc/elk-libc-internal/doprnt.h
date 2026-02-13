#ifndef __ELK_LIBC_INTERNAL__DOPRNT__
#define __ELK_LIBC_INTERNAL__DOPRNT__

#include <stdarg.h>

int
doprnt(
        int(*putchar)(int c, void *state),
        void *state,
        const char *fmt,
        va_list arg);

#endif
