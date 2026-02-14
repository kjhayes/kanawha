
#include <stdlib.h>
#include <stdint.h>

#if __SIZEOF_INT__ == 8
#define MODULUS    (1U << 63)
#define MULTIPLIER (6364136223846793005U)
#define INCREMENT  (1U)
#endif

#if __SIZEOF_INT__ == 4
#define MODULUS    (1U << 31)
#define MULTIPLIER (1103515245U)
#define INCREMENT  (12345U)
#endif

#if __SIZEOF_INT__ == 2
#define MODULUS (1U << 15)
#define MULTIPLIER (47474U)
#define INCREMENT  (1U)
#endif

#ifndef MODULUS
#error "elk libc rand() is not defined for the current sizeof(unsigned int)!"
#endif

static unsigned int _seed = 1;

int rand_r(unsigned int *seedp)
{
    unsigned int cur = *seedp;
    cur = (MULTIPLIER * cur + INCREMENT) % MODULUS;
    *seedp = cur;
    return cur;
}

int rand(void)
{
    return rand_r(&_seed);
}

void srand(unsigned int seed)
{
    _seed = seed;
}

