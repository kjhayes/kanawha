#ifndef __KANAWHA__UAPI_FB_H__
#define __KANAWHA__UAPI_FB_H__

#include <kanawha/uapi/gfx.h>

// Layer Info
struct fb_layer_info
{
    struct gfx_layout layout;
};

// Mode Info
struct fb_mode_info
{
    unsigned long buffer_size;
    unsigned long layer_count;
    struct fb_layer_info layer_infos[];
};

#endif
