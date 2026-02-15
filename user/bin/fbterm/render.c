
#include "term.h"
#include "font.h"
#include <kfb/kfb.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

static inline void
render_graphical_glyph(
	size_t x,
	size_t y,
	struct terminal_data *tdata,
	struct font_data *fdata,
	struct kfb_framebuffer *fb,
	int layer)
{
    size_t layer_width = fb->current_mode_info->layer_infos[layer].layout.width;
    size_t layer_height = fb->current_mode_info->layer_infos[layer].layout.height;
    char c = terminal_data.character_buffer[x + (y * tdata->width)];
    color_t fg_color = terminal_data.fg_color_buffer[x + (y * tdata->width)];
    color_t bg_color = terminal_data.bg_color_buffer[x + (y * tdata->width)];
    struct kfb_image *fg_img = fdata->glyphs[c].fg;
    struct kfb_image *bg_img = fdata->glyphs[c].bg;
    if(x == tdata->cursor_x && y == tdata->cursor_y) {
        color_t temp = fg_color;
        fg_color = bg_color;
        bg_color = temp;
    }\
    size_t offset_x = (x*layer_width)/tdata->width;
    size_t offset_y = (y*layer_height)/tdata->height;
    kfb_rgba_t kfb_fg_color = {
        .r = fg_color.r,
        .g = fg_color.g,
        .b = fg_color.b,
        .a = fg_color.a,
    };
    kfb_rgba_t kfb_bg_color = {
        .r = bg_color.r,
        .g = bg_color.g,
        .b = bg_color.b,
        .a = bg_color.a,
    };
    kfb_blit_image_brightness_as_color_onto_layer(
            fb,
            layer,
            fg_img,
            offset_x, offset_y,
            layer_width/tdata->width, layer_height/tdata->height,
            kfb_fg_color);
    kfb_blit_image_brightness_as_color_onto_layer(
            fb,
            layer,
            bg_img,
            offset_x, offset_y,
            layer_width/tdata->width, layer_height/tdata->height,
            kfb_bg_color);
}

static inline void
render_ascii_glyph(
	size_t x,
	size_t y,
	struct terminal_data *tdata,
	struct kfb_framebuffer *fb,
	int layer)
{
    struct fb_layer_info *layer_info = &fb->current_mode_info->layer_infos[layer];

    size_t width =  layer_info->layout.width;
    size_t height = layer_info->layout.height;

    // Minimum of both dimensions
    if(tdata->width < width) {
	width = tdata->width;
    }
    if(tdata->height < height) {
	height = tdata->height;
    }

    if(x >= width) {
	return;
    }
    if(y >= height) {
	return;
    }

    size_t offset;
    switch(layer_info->layout.order) {
	case GFX_ORDER_ROW_MAJOR:
	    offset = x + (y * layer_info->layout.width);
	    break;
	case GFX_ORDER_COLUMN_MAJOR:
	    offset = y + (x * layer_info->layout.height);
	    break;
	default:
	    return;
    }

    offset *= layer_info->layout.stride;
    offset += layer_info->layout.offset;

    char c = terminal_data.character_buffer[x + (y * tdata->width)];

    kfb_framebuffer_copy_direct(
	    fb,
	    offset,
	    &c,
	    1);

    return;
}

static inline void
render_vga_attr(
	size_t x,
	size_t y,
	struct terminal_data *tdata,
	struct kfb_framebuffer *fb,
	int layer)
{
    struct fb_layer_info *layer_info = &fb->current_mode_info->layer_infos[layer];

    size_t width =  layer_info->layout.width;
    size_t height = layer_info->layout.height;

    // Minimum of both dimensions
    if(tdata->width < width) {
	width = tdata->width;
    }
    if(tdata->height < height) {
	height = tdata->height;
    }

    if(x >= width) {
	return;
    }
    if(y >= height) {
	return;
    }

    size_t offset;
    switch(layer_info->layout.order) {
	case GFX_ORDER_ROW_MAJOR:
	    offset = x + (y * layer_info->layout.width);
	    break;
	case GFX_ORDER_COLUMN_MAJOR:
	    offset = y + (x * layer_info->layout.height);
	    break;
	default:
	    return;
    }

    offset *= layer_info->layout.stride;
    offset += layer_info->layout.offset;

    char attr = 0x0;

    {
        color_t fg_color = terminal_data.fg_color_buffer[x + (y * tdata->width)];
        if(fg_color.r >= 0x80) {
            attr |= (1<<0);
        }
        if(fg_color.g >= 0x80) {
            attr |= (1<<1);
        }
        if(fg_color.b >= 0x80) {
            attr |= (1<<2);
        }

        uint32_t fg_avg = 0x0;
        fg_avg += fg_color.r;
        fg_avg += fg_color.g;
        fg_avg += fg_color.b;
        fg_avg /= 3;

        if(fg_avg >= 0x80 || fg_color.r >= 0xC0 || fg_color.g >= 0xC0 || fg_color.b >= 0xC0) {
            attr |= (1<<3);
        }
    }

    {
        color_t bg_color = terminal_data.bg_color_buffer[x + (y * tdata->width)];
        if(bg_color.r >= 0x80) {
            attr |= (1<<4);
        }
        if(bg_color.g >= 0x80) {
            attr |= (1<<5);
        }
        if(bg_color.b >= 0x80) {
            attr |= (1<<6);
        }

        uint32_t bg_avg = 0x0;
        bg_avg += bg_color.r;
        bg_avg += bg_color.g;
        bg_avg += bg_color.b;
        bg_avg /= 3;

        if(bg_avg > 0x80) {
            attr |= (1<<7);
        }
    }

    kfb_framebuffer_copy_direct(
	    fb,
	    offset,
	    &attr,
	    1);

    return;
}

static inline void
render_all(
	int force,
	struct terminal_data *tdata,
	struct font_data *fdata,
	struct kfb_framebuffer *fb,
	int *render_changed)
{
    for(size_t layer = 0; layer < fb->current_mode_info->layer_count; layer++) {
        for(size_t y = 0; y < tdata->height; y++) {
            for(size_t x = 0; x < tdata->width; x++) {
                if(force || terminal_data.redraw_buffer[x + (y*tdata->width)]) {
                    *render_changed = 1;
		    switch(fb->current_mode_info->layer_infos[layer].layout.format) {
			case GFX_FORMAT_ASCII:
			case GFX_FORMAT_VGA_CHAR:
			    render_ascii_glyph(x,y,tdata,fb,layer);
			    break;
			case GFX_FORMAT_VGA_ATTR:
			    render_vga_attr(x,y,tdata,fb,layer);
			    break;
			default:
                            render_graphical_glyph(x,y,tdata,fdata,fb,layer);
			    break;
		    }
                    terminal_data.redraw_buffer[x + (y*tdata->width)] = 0;
                }
            }
        }
    }
}

int
render_update(
        struct terminal_data *tdata,
        struct font_data *fdata,
        struct kfb_framebuffer *fb)
{
    int res;

#define RENDER_DELAY_MS 1
#define FORCE_FLUSH_AFTER 10

    int force = 1;
    int render_changed = 1;

    if(tdata->cur_fb_mode != tdata->req_fb_mode) {
        res = kfb_set_current_mode(fb, tdata->req_fb_mode);
        if(res) {
    	    tdata->req_fb_mode = tdata->cur_fb_mode;
        } else {
    	    tdata->cur_fb_mode = tdata->req_fb_mode;
	    size_t pix_width, pix_height;
	    switch(fb->current_mode_info->layer_infos[0].layout.format) {
		case GFX_FORMAT_ASCII:
		case GFX_FORMAT_VGA_CHAR:
		case GFX_FORMAT_VGA_ATTR:
		    terminal_resize(tdata,
			    fb->current_mode_info->layer_infos[0].layout.width,
			    fb->current_mode_info->layer_infos[0].layout.height);
		    break;
		default:
		   pix_width = fb->current_mode_info->layer_infos[0].layout.width;
		   pix_height = fb->current_mode_info->layer_infos[0].layout.height;
		   terminal_resize(tdata,
			   pix_width / fdata->width,
			   pix_height / fdata->height);
		   break;
	    }
        }
        force = 1;
    }

    render_all(force, tdata, fdata, fb, &render_changed);
    if(render_changed || force) {
        kfb_flush_framebuffer(fb);
        render_changed = 0;
	force = 0;
    }
        
    return 0;
}
