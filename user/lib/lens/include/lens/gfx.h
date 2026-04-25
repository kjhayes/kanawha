#ifndef __KANAWHA__LENS_GFX_H__
#define __KANAWHA__LENS_GFX_H__

#include <kanawha/gfx.h>
#include <lens/lens.h>
#include <stdint.h>
#include <stddef.h>

struct lens_gfx_info
{
    uint64_t frame_size;
    uint8_t num_layers;
    struct gfx_layout layer_layout[];
};

#endif
