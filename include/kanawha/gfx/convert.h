#ifndef __KANAWHA__GFX_CONVERT_H__
#define __KANAWHA__GFX_CONVERT_H__

#include <kanawha/gfx/layout.h>
#include <kanawha/types.h>

int
gfx_convert(struct gfx_layout *in_layout,
            void *in_buf,
            size_t in_buflen,
            struct gfx_layout *out_layout,
            void *out_buf,
            size_t out_buflen);

#endif
