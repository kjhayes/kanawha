
#include <byteswap.h>

uint16_t
bswap_16(uint16_t x)
{
    return __builtin_bswap16(x);
}
uint32_t
bswap_32(uint32_t x)
{
    return __builtin_bswap32(x);
}
uint64_t
bswap_64(uint64_t x)
{
    return __builtin_bswap64(x);
}
