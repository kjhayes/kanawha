#ifndef __KANAWHA_DEVICETREE_TYPES_H__
#define __KANAWHA_DEVICETREE_TYPES_H__

#include <kanawha/endian.h>

typedef be64_t fdt64_t;
typedef be32_t fdt32_t;
typedef be16_t fdt16_t;
typedef uint8_t fdt8_t;

static inline uint16_t
fdttoh16(fdt16_t from)
{
    return betoh16(from);
}
static inline fdt16_t
htofdt16(uint16_t from)
{
    return htobe16(from);
}
static inline uint32_t
fdttoh32(fdt32_t from)
{
    return betoh32(from);
}
static inline fdt32_t
htofdt32(uint32_t from)
{
    return htobe32(from);
}
static inline uint64_t
fdttoh64(fdt64_t from)
{
    return betoh64(from);
}
static inline fdt64_t
htofdt64(uint64_t from)
{
    return htobe64(from);
}

#endif
