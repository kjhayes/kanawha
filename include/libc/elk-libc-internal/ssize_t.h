#ifndef __ELK_LIBC_INTERNAL__SSIZE_T_H__
#define __ELK_LIBC_INTERNAL__SSIZE_T_H__

#ifndef __INTPTR_TYPE__
#error "Elk <elk-libc-internal/ssize_t.h> needs __INTPTR_TYPE__ to be defined!"
#else
typedef __INTPTR_TYPE__ ssize_t;
#endif

#endif
