#ifndef __KANAWHA__GFX_IMAGE_H__
#define __KANAWHA__GFX_IMAGE_H__

#include <stdint.h>
#include <kanawha/gfx/layout.h>

#ifdef CONFIG_LOGO_DATA
#define KANAWHA_LOGO_HEIGHT 78
#define KANAWHA_LOGO_WIDTH 320
extern const uint8_t kanawha_logo_data[];
extern struct gfx_layout kanawha_logo_layout;
#endif

#endif
