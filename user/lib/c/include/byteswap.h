#ifndef __ELK_LIBC__BYTE_SWAP_H__
#define __ELK_LIBC__BYTE_SWAP_H__

#include <stdint.h>

uint16_t
bswap_16(uint16_t x);
uint32_t
bswap_32(uint32_t x);
uint64_t
bswap_64(uint64_t x);

#endif
