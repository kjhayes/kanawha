#ifndef __ELK_LIBC__ENDIAN_H__
#define __ELK_LIBC__ENDIAN_H__

#include <stdint.h>

#define LITTLE_ENDIAN (1)
#define BIG_ENDIAN (2)

#ifndef __ORDER_LITTLE_ENDIAN__
#error "Compiler did not provide __ORDER_LITTLE_ENDIAN__"
#endif
#ifndef __ORDER_BIG_ENDIAN__
#error "Compiler did not provide __ORDER_BIG_ENDIAN__"
#endif

#ifdef __BYTE_ORDER__
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define BYTE_ORDER LITTLE_ENDIAN
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BYTE_ORDER BIG_ENDIAN
#else
#error "Compiler did not provide standard __BYTE_ORDER__ value"
#endif
#else
#error "Compiler did not provide __BYTE_ORDER__"
#endif

uint16_t  be16toh(uint16_t);
uint32_t  be32toh(uint32_t);
uint64_t  be64toh(uint64_t);

uint16_t  htobe16(uint16_t);
uint32_t  htobe32(uint32_t);
uint64_t  htobe64(uint64_t);

uint16_t  htole16(uint16_t);
uint32_t  htole32(uint32_t);
uint64_t  htole64(uint64_t);

uint16_t  le16toh(uint16_t);
uint32_t  le32toh(uint32_t);
uint64_t  le64toh(uint64_t);

#endif
