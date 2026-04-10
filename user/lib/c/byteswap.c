
#include <byteswap.h>

#define HAVE_BUILTIN_BSWAP
#ifdef __riscv64__
#undef HAVE_BUILTIN_BSWAP
#endif

uint16_t
bswap_16(uint16_t x)
{
#ifdef HAVE_BUILTIN_BSWAP
    return __builtin_bswap16(x);
#else
    uint16_t low = x & 0xFF;
    uint16_t high = (x>>8) & 0xFF;
    return (low<<8) | high;
#endif
}
uint32_t
bswap_32(uint32_t x)
{
#ifdef HAVE_BUILTIN_BSWAP
    return __builtin_bswap32(x);
#else
    uint32_t low = x & 0xFFFF;
    uint32_t high = (x>>16) & 0xFFFF;
    low = bswap_16(low);
    high = bswap_16(high);
    return (low<<16) | high;
#endif
}
uint64_t
bswap_64(uint64_t x)
{
#ifdef HAVE_BUILTIN_BSWAP
    return __builtin_bswap64(x);
#else
    uint64_t low = x & 0xFFFFFFFF;
    uint64_t high = (x>>32) & 0xFFFFFFFF;
    low = bswap_32(low);
    high = bswap_32(high);
    return (low<<32) | high;
#endif
}
