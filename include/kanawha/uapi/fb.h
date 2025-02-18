#ifndef __KANAWHA__UAPI_FB_H__
#define __KANAWHA__UAPI_FB_H__

#include <stdint.h>

// Layer Pixel Format
#define FB_LAYER_FORMAT_UNDEFINED (0)

// Little Endian, Single Byte Per Each of R (Red) G (Green) B (Blue) A (Alpha)
#define FB_LAYER_FORMAT_RGBA32    (1)
#define FB_LAYER_FORMAT_BGRA32    (2)
#define FB_LAYER_FORMAT_GRBA32    (3)
#define FB_LAYER_FORMAT_GBRA32    (4)
#define FB_LAYER_FORMAT_RBGA32    (5)
#define FB_LAYER_FORMAT_BRGA32    (6)

// 8-bit, 16-bit, etc. monochromatic brightness
#define FB_LAYER_FORMAT_MONO8  (7)
#define FB_LAYER_FORMAT_MONO16 (8)
#define FB_LAYER_FORMAT_MONO32 (9)
#define FB_LAYER_FORMAT_MONO64 (10)

#define FB_LAYER_FORMAT_ASCII     (11) // Single byte ascii character
#define FB_LAYER_FORMAT_VGA_CHAR  (12) // Single byte VGA character
#define FB_LAYER_FORMAT_VGA_ATTR  (13) // Single byte VGA attribute

#define FB_LAYER_FORMAT_BYTE_R3G3B2     (16) // Single byte with bit layout  | r2 | r1 | r0 | g2 | g1 | g0 | b1 | b0 |
#define FB_LAYER_FORMAT_BYTE_R1G1B1I1 (17) // bit layout | 0000 | r0 | g0 | b0 | i0 |
#define FB_LAYER_FORMAT_BYTE_R1G2B1   (18) // bit layout | 0000 | r0 | g1 | g0 | b0 |

// Order of pixels in the layer
#define FB_LAYER_ORDER_UNDEFINED    (0)
#define FB_LAYER_ORDER_ROW_MAJOR    (1)
#define FB_LAYER_ORDER_COLUMN_MAJOR (2)

struct fb_layer_info {
    // FB_LAYER_FORMAT_*
    uint32_t format;
    // FB_LAYER_ORDER_*
    uint32_t order;

    uint64_t width;
    uint64_t height;

    uint64_t offset; // Offset before the first pixel in this layer
    uint64_t stride; // Stride between pixels (0 if packed)
};

// Mode Info
struct fb_mode_info
{
    uint64_t buffer_size;
    uint32_t layer_count;
    struct fb_layer_info layer_infos[];
};

#endif
