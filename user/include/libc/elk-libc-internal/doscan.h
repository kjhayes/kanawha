#ifndef __ELK_LIBC_INTERNAL__DOSCAN_H__
#define __ELK_LIBC_INTERNAL__DOSCAN_H__

#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>

int
doscan(
        int(*consumestr)(size_t len, void *state),
        const char*(*peekstr)(size_t min_len, size_t max_len, void *state),
        void *state,
        const char *fmt,
        va_list arg);

#endif
