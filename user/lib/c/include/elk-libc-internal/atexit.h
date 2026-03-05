#ifndef __ELK_LIBC_INTERNAL__ATEXIT_H__
#define __ELK_LIBC_INTERNAL__ATEXIT_H__

#define ATEXIT_MAX_HANDLERS (128)
extern size_t __elk_libc_internal__atexit_count;
extern void (*__elk_libc_internal__atexit_array[ATEXIT_MAX_HANDLERS])(void);

void
__elk_libc_internal__do_atexit(void);

#endif
