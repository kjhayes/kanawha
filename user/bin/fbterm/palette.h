#ifndef __FBTERM__PALETTE_H__
#define __FBTERM__PALETTE_H__

#include <stddef.h>
#include "color.h"

struct palette
{
    size_t num_colors;
    color_t(*read_color)(size_t index);
};

static inline color_t
palette_read_color(
        struct palette *p,
        size_t index)
{
    if(index < p->num_colors) {
        return (*p->read_color)(index);
    } else {
        color_t ret = {
            .r = 0x00,
            .g = 0x00,
            .b = 0x00,
            .a = 0xFF,
        };
        return ret;
    }
}

#endif
