#ifndef __ELK_LIBC__ALLOCA_H__
#define __ELK_LIBC__ALLOCA_H__

#include <stddef.h>

#ifndef alloca
#define alloca(...) __builtin_alloca(__VA_ARGS__)
#endif

#endif
