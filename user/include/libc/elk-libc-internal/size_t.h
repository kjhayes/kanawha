#ifndef __ELK_LIBC_INTERNAL__SIZE_T_H__
#define __ELK_LIBC_INTERNAL__SIZE_T_H__

#ifndef __SIZE_TYPE__
#error "Elk <elk-libc-internal/size_t.h> needs __SIZE_TYPE__ to be defined!"
#else
typedef __SIZE_TYPE__ size_t;
#endif

#endif
