
#include "render.h"
#include "font.h"
#include "term.h"
#include <kanawha/gfx.h>
#include <kfb/kfb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static inline void
render_graphical_glyph(size_t x,
                       size_t y,
                       struct terminal_data *tdata,
                       struct font_data *fdata,
                       struct gfx_layout *layout,
                       void *buffer,
                       size_t buflen)
{
    size_t layer_width = layout->width;
    size_t layer_height = layout->height;
    char c = terminal_data.character_buffer[x + (y * tdata->width)];
    color_t fg_color = terminal_data.fg_color_buffer[x + (y * tdata->width)];
    color_t bg_color = terminal_data.bg_color_buffer[x + (y * tdata->width)];
    struct kfb_image *fg_img = fdata->glyphs[c].fg;
    struct kfb_image *bg_img = fdata->glyphs[c].bg;
    if(tdata->cursor_visible && (x == tdata->cursor_x && y == tdata->cursor_y))
    {
        color_t temp = fg_color;
        fg_color = bg_color;
        bg_color = temp;
    }
    size_t offset_x = (x * layer_width) / tdata->width;
    size_t offset_y = (y * layer_height) / tdata->height;
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
    kfb_blit_image_brightness_as_color(buffer,
                                       layer_width / tdata->width,
                                       layer_height / tdata->height,
                                       offset_x,
                                       offset_y,
                                       layout,
                                       fg_img,
                                       kfb_fg_color);
    kfb_blit_image_brightness_as_color(buffer,
                                       layer_width / tdata->width,
                                       layer_height / tdata->height,
                                       offset_x,
                                       offset_y,
                                       layout,
                                       bg_img,
                                       kfb_bg_color);
}

static inline void
render_ascii_glyph(size_t x,
                   size_t y,
                   struct terminal_data *tdata,
                   struct gfx_layout *layout,
                   void *buffer,
                   size_t buflen)
{
    size_t width = layout->width;
    size_t height = layout->height;

    // Minimum of both dimensions
    if(tdata->width < width)
    {
        width = tdata->width;
    }
    if(tdata->height < height)
    {
        height = tdata->height;
    }

    if(x >= width)
    {
        return;
    }
    if(y >= height)
    {
        return;
    }

    size_t offset;
    switch(layout->order)
    {
    case GFX_ORDER_ROW_MAJOR:
        offset = x + (y * layout->width);
        break;
    case GFX_ORDER_COLUMN_MAJOR:
        offset = y + (x * layout->height);
        break;
    default:
        return;
    }

    offset *= layout->stride;
    offset += layout->offset;

    char c = terminal_data.character_buffer[x + (y * tdata->width)];

    ((uint8_t *)buffer)[offset] = c;

    return;
}

static inline void
render_vga_attr(size_t x,
                size_t y,
                struct terminal_data *tdata,
                struct gfx_layout *layout,
                void *buffer,
                size_t buflen)
{
    size_t width = layout->width;
    size_t height = layout->height;

    // Minimum of both dimensions
    if(tdata->width < width)
    {
        width = tdata->width;
    }
    if(tdata->height < height)
    {
        height = tdata->height;
    }

    if(x >= width)
    {
        return;
    }
    if(y >= height)
    {
        return;
    }

    size_t offset;
    switch(layout->order)
    {
    case GFX_ORDER_ROW_MAJOR:
        offset = x + (y * layout->width);
        break;
    case GFX_ORDER_COLUMN_MAJOR:
        offset = y + (x * layout->height);
        break;
    default:
        return;
    }

    offset *= layout->stride;
    offset += layout->offset;

    char attr = 0x0;

    {
        color_t fg_color =
            terminal_data.fg_color_buffer[x + (y * tdata->width)];
        if(fg_color.r >= 0x80)
        {
            attr |= (1 << 0);
        }
        if(fg_color.g >= 0x80)
        {
            attr |= (1 << 1);
        }
        if(fg_color.b >= 0x80)
        {
            attr |= (1 << 2);
        }

        uint32_t fg_avg = 0x0;
        fg_avg += fg_color.r;
        fg_avg += fg_color.g;
        fg_avg += fg_color.b;
        fg_avg /= 3;

        if(fg_avg >= 0x80 || fg_color.r >= 0xC0 || fg_color.g >= 0xC0 ||
           fg_color.b >= 0xC0)
        {
            attr |= (1 << 3);
        }
    }

    {
        color_t bg_color =
            terminal_data.bg_color_buffer[x + (y * tdata->width)];
        if(bg_color.r >= 0x80)
        {
            attr |= (1 << 4);
        }
        if(bg_color.g >= 0x80)
        {
            attr |= (1 << 5);
        }
        if(bg_color.b >= 0x80)
        {
            attr |= (1 << 6);
        }

        uint32_t bg_avg = 0x0;
        bg_avg += bg_color.r;
        bg_avg += bg_color.g;
        bg_avg += bg_color.b;
        bg_avg /= 3;

        if(bg_avg > 0x80)
        {
            attr |= (1 << 7);
        }
    }

    ((uint8_t *)buffer)[offset] = attr;

    return;
}

static inline void
render_all(int force,
           struct terminal_data *tdata,
           struct font_data *fdata,
           struct gfx_layout *layout,
           void *buffer,
           size_t buflen,
           int *render_changed)
{
    for(size_t y = 0; y < tdata->height; y++)
    {
        for(size_t x = 0; x < tdata->width; x++)
        {
            if(force || terminal_data.redraw_buffer[x + (y * tdata->width)])
            {
                *render_changed = 1;
                switch(layout->format)
                {
                case GFX_FORMAT_ASCII:
                case GFX_FORMAT_VGA_CHAR:
                    render_ascii_glyph(x, y, tdata, layout, buffer, buflen);
                    break;
                case GFX_FORMAT_VGA_ATTR:
                    render_vga_attr(x, y, tdata, layout, buffer, buflen);
                    break;
                default:
                    render_graphical_glyph(x,
                                           y,
                                           tdata,
                                           fdata,
                                           layout,
                                           buffer,
                                           buflen);
                    break;
                }
            }
        }
    }
}

static int first_updates = 100;

int
render_update(struct terminal_data *tdata,
              struct font_data *fdata,
              struct render_ctx *ctx)
{
    int res;

    int force = 0;

    if(first_updates)
    {
        force = 1;
        first_updates--;
    }

    struct gfx_layout layout;
    void *buffer;
    size_t buflen;

    size_t layer_i = 0;

    while(1)
    {
        res = render_ctx_begin(ctx, layer_i, &layout, &buffer, &buflen);
        if(res)
        {
            break;
        }

        size_t pix_width, pix_height;
        switch(layout.format)
        {
        case GFX_FORMAT_ASCII:
        case GFX_FORMAT_VGA_CHAR:
        case GFX_FORMAT_VGA_ATTR:
            terminal_resize(tdata, layout.width, layout.height);
            break;
        default:
            pix_width = layout.width;
            pix_height = layout.height;
            terminal_resize(tdata,
                            pix_width / fdata->width,
                            pix_height / fdata->height);
            break;
        }

        int render_changed = 0;
        render_all(force,
                   tdata,
                   fdata,
                   &layout,
                   buffer,
                   buflen,
                   &render_changed);

        render_ctx_end(ctx, layer_i, render_changed || force);

        layer_i++;
    }

    memset(tdata->redraw_buffer, 0, tdata->width * tdata->height);

    return 0;
}
