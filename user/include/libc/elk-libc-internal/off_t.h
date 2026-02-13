#ifndef __ELK_LIBC_INTERNAL__OFF_T_H__
#define __ELK_LIBC_INTERNAL__OFF_T_H__

#ifndef __SIZE_TYPE__
#error "Elk <elk-libc-internal/off_t.h> needs __SIZE_TYPE__ to be defined!"
#else
typedef __SIZE_TYPE__ off_t;
#endif

#endif
