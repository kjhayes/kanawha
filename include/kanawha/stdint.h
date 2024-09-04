#ifndef __KANAWHA_STDINT_H__
#define __KANAWHA_STDINT_H__

#define NULL (void*)0

#define PAGE_SIZE_4KB (1ULL<<12)
#define PAGE_SIZE_2MB (1ULL<<20)
#define PAGE_SIZE_1GB (1ULL<<30)

#define I8_TYPE  char
#define I16_TYPE short
#define I32_TYPE int
#define I64_TYPE long

_Static_assert(sizeof(I8_TYPE) == 1, "I8_TYPE is not exactly 1 byte wide!");
_Static_assert(sizeof(I16_TYPE) == 2, "I16_TYPE is not exactly 2 bytes wide!");
_Static_assert(sizeof(I32_TYPE) == 4, "I32_TYPE is not exactly 4 bytes wide!");
_Static_assert(sizeof(I64_TYPE) == 8, "I64_TYPE is not exactly 8 bytes wide!");

typedef I8_TYPE int8_t;
typedef unsigned I8_TYPE uint8_t;
typedef I16_TYPE int16_t;
typedef unsigned I16_TYPE uint16_t;
typedef I32_TYPE int32_t;
typedef unsigned I32_TYPE uint32_t;
typedef I64_TYPE int64_t;
typedef unsigned I64_TYPE uint64_t;

#if defined(CONFIG_X64)
typedef uint64_t uintptr_t;
typedef uint64_t size_t;
typedef int64_t ssize_t;
#else
#error "Architecture does not define uintptr_t and size_t!"
#endif

_Static_assert(sizeof(void*) <= sizeof(uintptr_t), "sizeof(void*) is greater than sizeof(uintptr_t)!");

typedef uintptr_t paddr_t;
typedef uintptr_t vaddr_t;
typedef unsigned int order_t;

// Shorthand (Really should only be used in printk format casting)
typedef signed s_t;
typedef signed long sl_t;
typedef signed long long sll_t;

typedef unsigned u_t;
typedef unsigned long ul_t;
typedef unsigned long long ull_t;

#endif
