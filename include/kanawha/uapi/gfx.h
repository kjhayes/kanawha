#ifndef __KANAWHA__UAPI_GFX_H__
#define __KANAWHA__UAPI_GFX_H__

#include <stdint.h>

// Layer Pixel Format
#define GFX_FORMAT_UNDEFINED (0)

// Little Endian, Single Byte Per Each of R (Red) G (Green) B (Blue) A (Alpha)
#define GFX_FORMAT_RGBA32 (1)
#define GFX_FORMAT_BGRA32 (2)
#define GFX_FORMAT_GRBA32 (3)
#define GFX_FORMAT_GBRA32 (4)
#define GFX_FORMAT_RBGA32 (5)
#define GFX_FORMAT_BRGA32 (6)

// 8-bit, 16-bit, etc. monochromatic brightness
#define GFX_FORMAT_MONO8 (7)
#define GFX_FORMAT_MONO16 (8)
#define GFX_FORMAT_MONO32 (9)
#define GFX_FORMAT_MONO64 (10)

#define GFX_FORMAT_ASCII (11)    // Single byte ascii character
#define GFX_FORMAT_VGA_CHAR (12) // Single byte VGA character
#define GFX_FORMAT_VGA_ATTR (13) // Single byte VGA attribute

#define GFX_FORMAT_BYTE_R3G3B2                                                 \
    (16) // Single byte with bit layout  | b1 | b0 | g2 | g1 | g0 | r2 | r1 |
         // r0
         // |
#define GFX_FORMAT_BYTE_R1G1B1I1 (17) // bit layout | 0000 | i0 | b0 | g0 | r0 |
#define GFX_FORMAT_BYTE_R1G2B1 (18)   // bit layout | 0000 | b0 | g1 | g0 | r0 |

#define GFX_FORMAT_BIT_MONO                                                    \
    (19) // Monochrome (BITWISE) (most significant bit on left)

// Order of pixels in the layer
#define GFX_ORDER_UNDEFINED (0)
#define GFX_ORDER_ROW_MAJOR (1)
#define GFX_ORDER_COLUMN_MAJOR (2)

static inline int
gfx_format_is_bitwise(unsigned long format)
{
    switch(format)
    {
    case GFX_FORMAT_BIT_MONO:
        return 1;
    }
    return 0;
}

struct gfx_layout
{
    unsigned long format; // GFX_FORMAT_*
    unsigned long order;  // GFX_ORDER_*
    unsigned long width;  // in pixels
    unsigned long height; // in pixels
    unsigned long offset; // Offset before the first pixel in this layer (byte
                          // or bit depending on format)
    unsigned long stride; // Stride between pixels (1 for single (byte or bit
                          // depending on format) pixels)
};

#endif
