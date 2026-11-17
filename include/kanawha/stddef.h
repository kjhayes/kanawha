#ifndef __KANAWHA__STDDEF_H__
#define __KANAWHA__STDDEF_H__

#include <kanawha/types.h>

static inline int
popcountul(unsigned long x)
{
#if defined(CONFIG_TOOLCHAIN_SUPPORTS_BUILTIN_POPCOUNT) \
    && defined(__has_builtin) \
    && __has_builtin(__builtin_popcountl)

    if(x == 0) {
        return 0;
    }
    return __builtin_popcountl(x);

#else

    // Default back to Kerninghan's Alg. (O(n) in the number set bits)
    int popcount = 0;
    while(x != 0) {
        popcount++;
        x &= (x-1);
    }
    return popcount;

#endif
}

static inline int
clzul(unsigned long x)
{
#if defined(CONFIG_TOOLCHAIN_SUPPORTS_BUILTIN_CLZ) \
    && defined(__has_builtin) \
    && __has_builtin(__builtin_clzl)

    if(x == 0) {
        return 8 * sizeof(x);
    }
    return __builtin_clzl(x);

#else

    int bits = 8 * sizeof(x);

    if(x == 0) {
        return bits;
    }

    int count = 0;
    while(x && bits) { // Loop while "x" has any set bit

        int half_bits = bits >> 1;

        // We only consider the least-significant
        // "bits" bits of "x" during each iteration
        if(x >> half_bits) {
            // There is a set bit in the left half of
            // the bits we are considering, shift "x"
            // to focus on that half, and subtract out
            // the right half from the number of possible
            // leading bits
            x >>= half_bits;
        } else {
            // The left hand side is all zeros, add them
            // into the count
            count += half_bits;
        }

        // We are considering a smaller region
        // in the next iteration
        bits = half_bits;
    }

    return count;

#endif
}

#define alignof(x) __alignof__(x)
#define offsetof(type, member) __builtin_offsetof(type, member)
#define container_of(ptr, type, member)                                        \
    ({                                                                         \
        const typeof(((type *)0)->member) *__mptr = (ptr);                     \
        (type *)((char *)__mptr - offsetof(type, member));                     \
    })

// Just double checking for ptr_orderof
_Static_assert(sizeof(void *) == sizeof(unsigned int) ||
                   sizeof(void *) == sizeof(unsigned long) ||
                   sizeof(void *) == sizeof(unsigned long long),
               "Pointer size is not equal to any available integral type!");

// Gives the maximum alignment order of a pointer
#define ptr_orderof(ptr)                                                       \
    (((uintptr_t)ptr == 0)                                                     \
         ? (sizeof(void *) * 8)                                                \
         : (sizeof(void *) == sizeof(unsigned int)                             \
                ? __builtin_ctz((unsigned int)(uintptr_t)ptr)                  \
                : (sizeof(void *) == sizeof(unsigned long)                     \
                       ? __builtin_ctzl((unsigned long)(uintptr_t)ptr)         \
                       : (sizeof(void *) == sizeof(unsigned long long)         \
                              ? __builtin_ctzll(                               \
                                    (unsigned long long)(uintptr_t)ptr)        \
                              : 0))))

// Similar to alignof but returns the "order" not the "size"
// e.g.
//     alignof(uint64_t) = 8
//     orderof(uint64_t) = 3
#define orderof(x) ptr_orderof((void *)alignof(x))

// Gives the minimum power of two which is larger than the provided value
#define round_up_order(x)                                                      \
    ((((unsigned long)x) == 0)                                                 \
         ? (0)                                                                 \
         : ((popcountul((unsigned long)x) == 1)                                \
                ? (clzul((unsigned long)x))                                    \
                : (((sizeof(unsigned long) * 8ULL)) -                          \
                   clzul((unsigned long)x))))

#define MIN(x, y) (x > y ? y : x)
#define MAX(x, y) (x < y ? y : x)

#define is_pow2(x) ((x > 0) && ((x & (x - 1)) == 0))

#endif
