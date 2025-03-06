#ifndef __KANAWHA__ENDIAN_H__
#define __KANAWHA__ENDIAN_H__

#include <kanawha/arch.h>
#include <kanawha/types.h>
#include <kanawha/printk.h>

typedef __bitwise uint16_t le16_t;
typedef __bitwise uint16_t be16_t;

typedef __bitwise uint32_t le32_t;
typedef __bitwise uint32_t be32_t;

typedef __bitwise uint64_t le64_t;
typedef __bitwise uint64_t be64_t;

static inline uint16_t
byteswap16(uint16_t value)
{
    return __builtin_bswap16(value);
}
static inline uint32_t
byteswap32(uint32_t value)
{
    return __builtin_bswap32(value);
}
static inline uint64_t
byteswap64(uint64_t value)
{
    return __builtin_bswap64(value);
}

static inline uint16_t
betoh16(be16_t from)
{
    switch(kernel_endian) {
        case ENDIAN_BIG:
            return (uint16_t)from;
        case ENDIAN_LITTLE:
            return byteswap16((uint16_t)from);
        default:
            wprintk("betoh16 with ENDIAN_MIXED!\n");
            return (uint16_t)from;
    }
}
static inline uint32_t
betoh32(be32_t from)
{
    switch(kernel_endian) {
        case ENDIAN_BIG:
            return (uint32_t)from;
        case ENDIAN_LITTLE:
            return byteswap32((uint32_t)from);
        default:
            wprintk("betoh32 with ENDIAN_MIXED!\n");
            return (uint32_t)from;
    }
}
static inline uint64_t
betoh64(be64_t from)
{
    switch(kernel_endian) {
        case ENDIAN_BIG:
            return (uint64_t)from;
        case ENDIAN_LITTLE:
            return byteswap64((uint64_t)from);
        default:
            wprintk("betoh64 with ENDIAN_MIXED!\n");
            return (uint64_t)from;
    }
}
static inline uint16_t
letoh16(le16_t from)
{
    switch(kernel_endian) {
        case ENDIAN_LITTLE:
            return (uint16_t)from;
        case ENDIAN_BIG:
            return byteswap16((uint16_t)from);
        default:
            wprintk("letoh16 with ENDIAN_MIXED!\n");
            return (uint16_t)from;
    }
}
static inline uint32_t
letoh32(le32_t from)
{
    switch(kernel_endian) {
        case ENDIAN_LITTLE:
            return (uint32_t)from;
        case ENDIAN_BIG:
            return byteswap32((uint32_t)from);
        default:
            wprintk("letoh32 with ENDIAN_MIXED!\n");
            return (uint32_t)from;
    }
}
static inline uint64_t
letoh64(le64_t from)
{
    switch(kernel_endian) {
        case ENDIAN_LITTLE:
            return (uint64_t)from;
        case ENDIAN_BIG:
            return byteswap64((uint64_t)from);
        default:
            wprintk("letoh64 with ENDIAN_MIXED!\n");
            return (uint64_t)from;
    }
}

static inline be16_t
htobe16(uint16_t from)
{
    return betoh16(from);
}
static inline be32_t
htobe32(uint32_t from)
{
    return betoh32(from);
}
static inline be64_t 
htobe64(uint64_t from)
{
    return betoh64(from);
}

static inline le16_t
htole16(uint16_t from)
{
    return letoh16(from);
}
static inline le32_t
htole32(uint32_t from)
{
    return letoh32(from);
}
static inline le64_t 
htole64(uint64_t from)
{
    return letoh64(from);
}

#endif
