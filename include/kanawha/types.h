#ifndef __KANAWHA_TYPES_H__
#define __KANAWHA_TYPES_H__

#include <stdint.h>

#ifdef CONFIG_TOOLCHAIN_SUPPORTS_BITWISE_ATTRIBUTE
#define __bitwise __attribute__((bitwise))
#else
#define __bitwise
#endif

#undef NULL
#define NULL ((void*)0)

#define PAGE_SIZE_4KB (1ULL<<12)
#define PAGE_SIZE_2MB (1ULL<<20)
#define PAGE_SIZE_1GB (1ULL<<30)

#if defined(CONFIG_X64)
typedef uint64_t uintptr_t;
typedef uint64_t size_t;
typedef int64_t ssize_t;
#elif defined(CONFIG_RISCV64)
typedef uint64_t uintptr_t;
typedef uint64_t size_t;
typedef int64_t ssize_t;
#else
#error "Architecture does not define uintptr_t and size_t!"
#endif

_Static_assert(sizeof(void*) <= sizeof(uintptr_t), "sizeof(void*) is greater than sizeof(uintptr_t)!");

typedef unsigned int order_t;

// Shorthand (Really should only be used in printk format casting)
typedef signed s_t;
typedef signed long sl_t;
typedef signed long long sll_t;

typedef unsigned u_t;
typedef unsigned long ul_t;
typedef unsigned long long ull_t;

#endif
