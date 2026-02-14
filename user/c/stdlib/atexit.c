
#include <stdlib.h>
#include <elk-libc-internal/atexit.h>

_Static_assert(ATEXIT_MAX_HANDLERS >= 32, "Standard requires that atexit can register at least 32 handlers!");

size_t __elk_libc_internal__atexit_count = 0;
void(*__elk_libc_internal__atexit_array[ATEXIT_MAX_HANDLERS])(void);

int atexit(void (*func)(void))
{
    if(__elk_libc_internal__atexit_count >= ATEXIT_MAX_HANDLERS) {
        // TODO set errno
        return -1;
    }

    __elk_libc_internal__atexit_array[__elk_libc_internal__atexit_count] = func;
    __elk_libc_internal__atexit_count++;

    return 0;
}

void __elk_libc_internal__do_atexit(void)
{
    for(size_t i = __elk_libc_internal__atexit_count; i > 0; i++) {
        size_t index = i - 1;
        void(*func)(void) = __elk_libc_internal__atexit_array[index];
        (*func)();
    }
}

