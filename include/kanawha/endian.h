#ifndef __KANAWHA__ENDIAN_H__
#define __KANAWHA__ENDIAN_H__

#include <kanawha/arch.h>
#include <kanawha/types.h>
#include <kanawha/printk.h>
#include <kanawha/assert.h>

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

// "both" endian encodings
typedef struct {
    le16_t little;
    be16_t big;
} lebe16_t;
ASSERT_TYPE_SIZE(lebe16_t, 4);
typedef struct {
    le32_t little;
    be32_t big;
} lebe32_t;
ASSERT_TYPE_SIZE(lebe32_t, 8);
typedef struct {
    le64_t little;
    be64_t big;
} lebe64_t;
ASSERT_TYPE_SIZE(lebe64_t, 16);

typedef struct {
    be16_t big;
    le16_t little;
} bele16_t;
ASSERT_TYPE_SIZE(bele16_t, 4);
typedef struct {
    be32_t big;
    le32_t little;
} bele32_t;
ASSERT_TYPE_SIZE(bele32_t, 8);
typedef struct {
    be64_t big;
    le64_t little;
} bele64_t;
ASSERT_TYPE_SIZE(bele64_t, 16);

// To Host
static inline uint16_t
lebetoh16(lebe16_t from) {
    switch(kernel_endian) {
        case ENDIAN_BIG:
            return from.big;
        case ENDIAN_LITTLE:
            return from.little;
        default:
            return letoh16(from.little);
    }
}
static inline uint32_t
lebetoh32(lebe32_t from) {
    switch(kernel_endian) {
        case ENDIAN_BIG:
            return from.big;
        case ENDIAN_LITTLE:
            return from.little;
        default:
            return letoh32(from.little);
    }
}
static inline uint64_t
lebetoh64(lebe64_t from) {
    switch(kernel_endian) {
        case ENDIAN_BIG:
            return from.big;
        case ENDIAN_LITTLE:
            return from.little;
        default:
            return letoh64(from.little);
    }
}

static inline uint16_t
beletoh16(bele16_t from) {
    switch(kernel_endian) {
        case ENDIAN_BIG:
            return from.big;
        case ENDIAN_LITTLE:
            return from.little;
        default:
            return letoh16(from.little);
    }
}
static inline uint32_t
beletoh32(bele32_t from) {
    switch(kernel_endian) {
        case ENDIAN_BIG:
            return from.big;
        case ENDIAN_LITTLE:
            return from.little;
        default:
            return letoh32(from.little);
    }
}
static inline uint64_t
beletoh64(bele64_t from) {
    switch(kernel_endian) {
        case ENDIAN_BIG:
            return from.big;
        case ENDIAN_LITTLE:
            return from.little;
        default:
            return letoh64(from.little);
    }
}

// To "Both Endian"

static inline lebe16_t
htolebe16(uint16_t from) {
    lebe16_t to;
    to.little = htole16(from);
    to.big = htobe16(from);
    return to;
}
static inline lebe32_t
htolebe32(uint32_t from) {
    lebe32_t to;
    to.little = htole32(from);
    to.big = htobe32(from);
    return to;
}
static inline lebe64_t
htolebe64(uint64_t from) {
    lebe64_t to;
    to.little = htole64(from);
    to.big = htobe64(from);
    return to;
}

static inline bele16_t
htobele16(uint16_t from) {
    bele16_t to;
    to.little = htole16(from);
    to.big = htobe16(from);
    return to;
}
static inline bele32_t
htobele32(uint32_t from) {
    bele32_t to;
    to.little = htole32(from);
    to.big = htobe32(from);
    return to;
}
static inline bele64_t
htobele64(uint64_t from) {
    bele64_t to;
    to.little = htole64(from);
    to.big = htobe64(from);
    return to;
}

#endif
