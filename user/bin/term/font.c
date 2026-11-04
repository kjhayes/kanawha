
#include "font.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GLYPH_FORMAT GFX_FORMAT_RGBA32

struct psf_1_header
{
    uint8_t magic[2];
    uint8_t flags;
    uint8_t glyph_size;
};

struct font_data *
load_font_from_buffer(void *buffer, size_t buflen)
{
    if(buflen < sizeof(struct psf_1_header)) {
        return NULL;
    }
    struct psf_1_header *psf_1_header = buffer;

    if(psf_1_header->magic[0] != 0x36 || psf_1_header->magic[1] != 0x04)
    {
        return NULL;
    }

    size_t font_data_size = psf_1_header->glyph_size * 256;
    if(buflen < sizeof(*psf_1_header) + font_data_size) {
        return NULL;
    }

    struct font_data *fdata = malloc(sizeof(struct font_data));
    if(fdata == NULL)
    {
        return NULL;
    }
    memset(fdata, 0, sizeof(struct font_data));

    fdata->width = 8;
    fdata->height = psf_1_header->glyph_size;
    fdata->num_glyphs = 256;

    fdata->glyphs = malloc(sizeof(struct glyph_data) * fdata->num_glyphs);
    if(fdata->glyphs == NULL)
    {
        free(fdata);
        return NULL;
    }
    memset(fdata->glyphs, 0, sizeof(struct image *) * fdata->num_glyphs);

    for(size_t i = 0; i < fdata->num_glyphs; i++)
    {
        struct kfb_image *fg_img = malloc(sizeof(struct kfb_image));
        struct kfb_image *bg_img = malloc(sizeof(struct kfb_image));
        color_t *fg_pixel_data =
            malloc(sizeof(color_t) * fdata->width * fdata->height);
        color_t *bg_pixel_data =
            malloc(sizeof(color_t) * fdata->width * fdata->height);

        if(fg_img == NULL || bg_img == NULL || fg_pixel_data == NULL ||
           bg_pixel_data == NULL)
        {
            for(size_t fi = 0; fi < i; fi++)
            {
                free(fdata->glyphs[fi].fg->data);
                free(fdata->glyphs[fi].bg->data);
                free(fdata->glyphs[fi].fg);
                free(fdata->glyphs[fi].bg);
            }
            free(fdata->glyphs);
            free(fdata);
            free(fg_img);
            free(bg_img);
            free(fg_pixel_data);
            free(bg_pixel_data);
            return NULL;
        }

        fg_img->resx = fdata->width;
        fg_img->resy = fdata->height;
        fg_img->data = (void *)fg_pixel_data;
        fg_img->format = GLYPH_FORMAT;
        fg_img->order = GFX_ORDER_ROW_MAJOR;
        fg_img->stride = sizeof(color_t);
        fg_img->offset = 0;
        fg_img->data_size = fg_img->resx * fg_img->resy * sizeof(color_t);

        bg_img->resx = fdata->width;
        bg_img->resy = fdata->height;
        bg_img->data = (void *)bg_pixel_data;
        bg_img->format = GLYPH_FORMAT;
        bg_img->order = GFX_ORDER_ROW_MAJOR;
        bg_img->stride = sizeof(color_t);
        bg_img->offset = 0;
        bg_img->data_size = bg_img->resx * bg_img->resy * sizeof(color_t);

        // Render the image
        uint8_t *glyph = buffer + sizeof(struct psf_1_header) + (i * fdata->height);
        for(size_t fy = 0; fy < fdata->height; fy++)
        {
            uint8_t bits = glyph[fy];
            for(int fx = 0; fx < 8; fx++)
            {
                int value = (bits >> (7 - fx)) & 1;
                color_t *fg_pixel =
                    &((color_t *)fg_img->data)[fx + (fy * fdata->width)];
                color_t *bg_pixel =
                    &((color_t *)bg_img->data)[fx + (fy * fdata->width)];
                if(value)
                {
                    fg_pixel->r = 0xFF;
                    fg_pixel->g = 0xFF;
                    fg_pixel->b = 0xFF;
                    fg_pixel->a = 0xFF;
                    bg_pixel->r = 0x00;
                    bg_pixel->g = 0x00;
                    bg_pixel->b = 0x00;
                    bg_pixel->a = 0x00;
                }
                else
                {
                    fg_pixel->r = 0x00;
                    fg_pixel->g = 0x00;
                    fg_pixel->b = 0x00;
                    fg_pixel->a = 0x00;
                    bg_pixel->r = 0xFF;
                    bg_pixel->g = 0xFF;
                    bg_pixel->b = 0xFF;
                    bg_pixel->a = 0xFF;
                }
            }
        }

        fdata->glyphs[i].fg = fg_img;
        fdata->glyphs[i].bg = bg_img;
    }

    return fdata;
}

struct font_data *
load_font_from_file(const char *path)
{
    FILE *file = fopen(path, "r");
    if(file == NULL)
    {
        return NULL;
    }

    struct psf_1_header psf_1_header;
    size_t read = fread(&psf_1_header, sizeof(struct psf_1_header), 1, file);
    if(read != 1)
    {
        return NULL;
    }

    if(psf_1_header.magic[0] != 0x36 || psf_1_header.magic[1] != 0x04)
    {
        return NULL;
    }

    size_t font_data_size = psf_1_header.glyph_size * 256;
    uint8_t *font_data = malloc(sizeof(psf_1_header) + font_data_size);
    if(font_data == NULL)
    {
        return NULL;
    }

    memcpy(font_data, &psf_1_header, sizeof(psf_1_header));

    read = fread(font_data + sizeof(psf_1_header), font_data_size, 1, file);
    if(read != 1)
    {
        free(font_data);
        return NULL;
    }

    struct font_data *data;
    data = load_font_from_buffer(font_data, sizeof(psf_1_header) + font_data_size);
    free(font_data);

    fclose(file);
    return data;
}

void
unload_font(struct font_data *fdata)
{
    for(size_t i = 0; i < fdata->num_glyphs; i++)
    {
        free(fdata->glyphs[i].fg->data);
        free(fdata->glyphs[i].bg->data);
        free(fdata->glyphs[i].fg);
        free(fdata->glyphs[i].bg);
    }
    free(fdata->glyphs);
    free(fdata);
}


static uint8_t kanawha_default_font_data[256][8];

struct font_data *
load_default_font(void)
{
    struct font_data *fdata = malloc(sizeof(struct font_data));
    if(fdata == NULL)
    {
        return NULL;
    }
    memset(fdata, 0, sizeof(struct font_data));

    fdata->width = 8;
    fdata->height = 8;
    fdata->num_glyphs = 256;

    fdata->glyphs = malloc(sizeof(struct glyph_data) * fdata->num_glyphs);
    if(fdata->glyphs == NULL)
    {
        free(fdata);
        return NULL;
    }
    memset(fdata->glyphs, 0, sizeof(struct image *) * fdata->num_glyphs);

    for(size_t i = 0; i < fdata->num_glyphs; i++) {
        uint8_t *c_bytes;
        c_bytes = ((uint8_t*)kanawha_default_font_data + (i*8));
        struct glyph_data *g = &fdata->glyphs[i];
        g->bg = malloc(sizeof(struct kfb_image));
        g->fg = malloc(sizeof(struct kfb_image));
        color_t *fg_pixel_data = malloc(sizeof(color_t) * 8 * 8);
        color_t *bg_pixel_data = malloc(sizeof(color_t) * 8 * 8);
        if(g->bg == NULL || g->fg == NULL || fg_pixel_data == NULL || bg_pixel_data == NULL) {
            free(g->bg);
            free(g->fg);
            free(fg_pixel_data);
            free(bg_pixel_data);
            break;
        }
        g->fg->resx = fdata->width;
        g->fg->resy = fdata->height;
        g->fg->data = (void *)fg_pixel_data;
        g->fg->format = GLYPH_FORMAT;
        g->fg->order = GFX_ORDER_ROW_MAJOR;
        g->fg->stride = sizeof(color_t);
        g->fg->offset = 0;
        g->fg->data_size = g->fg->resx * g->fg->resy * sizeof(color_t);

        g->bg->resx = fdata->width;
        g->bg->resy = fdata->height;
        g->bg->data = (void *)bg_pixel_data;
        g->bg->format = GLYPH_FORMAT;
        g->bg->order = GFX_ORDER_ROW_MAJOR;
        g->bg->stride = sizeof(color_t);
        g->bg->offset = 0;
        g->bg->data_size = g->bg->resx * g->bg->resy * sizeof(color_t);


        // Render the image
        for(size_t fy = 0; fy < fdata->height; fy++)
        {
            uint8_t bits = c_bytes[fy];
            for(int fx = 0; fx < 8; fx++)
            {
                int value = (bits >> (7 - fx)) & 1;
                color_t *fg_pixel =
                    &((color_t *)g->fg->data)[fx + (fy * fdata->width)];
                color_t *bg_pixel =
                    &((color_t *)g->bg->data)[fx + (fy * fdata->width)];
                if(value)
                {
                    fg_pixel->r = 0xFF;
                    fg_pixel->g = 0xFF;
                    fg_pixel->b = 0xFF;
                    fg_pixel->a = 0xFF;
                    bg_pixel->r = 0x00;
                    bg_pixel->g = 0x00;
                    bg_pixel->b = 0x00;
                    bg_pixel->a = 0x00;
                }
                else
                {
                    fg_pixel->r = 0x00;
                    fg_pixel->g = 0x00;
                    fg_pixel->b = 0x00;
                    fg_pixel->a = 0x00;
                    bg_pixel->r = 0xFF;
                    bg_pixel->g = 0xFF;
                    bg_pixel->b = 0xFF;
                    bg_pixel->a = 0xFF;
                }
            }
        }
    }

    return fdata;
}

static uint8_t kanawha_default_font_data[256][8] =
    {
        ['a'] =
            {
                0b00000000,
                0b00000000,
                0b01111101,
                0b10000011,
                0b10000001,
                0b10000011,
                0b01111101,
                0b00000000,
            },
        ['b'] =
            {
                0b10000000,
                0b10000000,
                0b10111110,
                0b11000001,
                0b10000001,
                0b11000001,
                0b10111110,
                0b00000000,
            },
        ['c'] =
            {
                0b00000000,
                0b00000000,
                0b01111111,
                0b10000000,
                0b10000000,
                0b10000000,
                0b01111111,
                0b00000000,
            },
        ['d'] =
            {
                0b00000001,
                0b00000001,
                0b01111101,
                0b10000011,
                0b10000001,
                0b10000011,
                0b01111101,
                0b00000000,
            },
        ['e'] =
            {
                0b00000000,
                0b00000000,
                0b01111111,
                0b10000001,
                0b11111110,
                0b10000000,
                0b01111111,
                0b00000000,
            },
        ['f'] =
            {
                0b00011111,
                0b00100000,
                0b00100000,
                0b11111100,
                0b00100000,
                0b00100000,
                0b00100000,
                0b00000000,
            },
        ['g'] =
            {
                0b00000000,
                0b00000000,
                0b01111101,
                0b10000011,
                0b10000001,
                0b01111111,
                0b00000001,
                0b01111110,
            },
        ['h'] =
            {
                0b10000000,
                0b10000000,
                0b10111110,
                0b11000001,
                0b10000001,
                0b10000001,
                0b10000001,
                0b00000000,
            },
        ['i'] =
            {
                0b00001000,
                0b00000000,
                0b00011000,
                0b00001000,
                0b00001000,
                0b00001000,
                0b01111110,
                0b00000000,
            },
        ['j'] =
            {
                0b00000001,
                0b00000000,
                0b00000001,
                0b00000001,
                0b00000001,
                0b00000001,
                0b00000001,
                0b11111110,
            },
        ['k'] =
            {
                0b10000000,
                0b10000011,
                0b10001100,
                0b10110000,
                0b11111110,
                0b10000001,
                0b10000001,
                0b00000000,
            },
        ['l'] =
            {
                0b00111000,
                0b00001000,
                0b00001000,
                0b00001000,
                0b00001000,
                0b00001000,
                0b01111110,
                0b00000000,
            },
        ['m'] =
            {
                0b00000000,
                0b00000000,
                0b01100110,
                0b10011001,
                0b10011001,
                0b10000001,
                0b10000001,
                0b00000000,
            },
        ['n'] =
            {
                0b00000000,
                0b00000000,
                0b11111110,
                0b10000001,
                0b10000001,
                0b10000001,
                0b10000001,
                0b00000000,
            },
        ['o'] =
            {
                0b00000000,
                0b00000000,
                0b01111110,
                0b10000001,
                0b10000001,
                0b10000001,
                0b01111110,
                0b00000000,
            },
        ['p'] =
            {
                0b00000000,
                0b00000000,
                0b11111110,
                0b10000001,
                0b11000001,
                0b10111110,
                0b10000000,
                0b10000000,
            },
        ['q'] =
            {
                0b00000000,
                0b00000000,
                0b01111111,
                0b10000001,
                0b10000001,
                0b01111101,
                0b00000001,
                0b00000001,
            },
        ['r'] =
            {
                0b00000000,
                0b00000000,
                0b01111111,
                0b10000000,
                0b10000000,
                0b10000000,
                0b10000000,
                0b00000000,
            },
        ['s'] =
            {
                0b00000000,
                0b00000000,
                0b01111111,
                0b10000000,
                0b01111110,
                0b00000001,
                0b11111110,
                0b00000000,
            },
        ['t'] =
            {
                0b00010000,
                0b00010000,
                0b11111110,
                0b00010000,
                0b00010000,
                0b00010000,
                0b00010000,
                0b00000000,
            },
        ['u'] =
            {
                0b00000000,
                0b00000000,
                0b10000001,
                0b10000001,
                0b10000001,
                0b10000011,
                0b01111101,
                0b00000000,
            },
        ['v'] =
            {
                0b00000000,
                0b00000000,
                0b10000001,
                0b10000001,
                0b01000010,
                0b00100100,
                0b00011000,
                0b00000000,
            },
        ['w'] =
            {
                0b00000000,
                0b00000000,
                0b10000001,
                0b10000001,
                0b10011001,
                0b10011001,
                0b01100110,
                0b00000000,
            },
        ['x'] =
            {
                0b00000000,
                0b00000000,
                0b11000011,
                0b00100100,
                0b00011000,
                0b01100110,
                0b11000011,
                0b00000000,
            },
        ['y'] =
            {
                0b00000000,
                0b00000000,
                0b10000001,
                0b10000001,
                0b10000001,
                0b01111111,
                0b00000001,
                0b01111110,
            },
        ['z'] =
            {
                0b00000000,
                0b00000000,
                0b11111111,
                0b00000100,
                0b00001000,
                0b00110000,
                0b11111111,
                0b00000000,
            },
        ['A'] =
            {
                0b00111100,
                0b01000010,
                0b10000001,
                0b10000001,
                0b11111111,
                0b10000001,
                0b10000001,
                0b00000000,
            },
        ['B'] =
            {
                0b11111110,
                0b10000001,
                0b10000001,
                0b11111110,
                0b10000001,
                0b10000001,
                0b11111110,
                0b00000000,
            },
        ['C'] =
            {
                0b01111111,
                0b10000000,
                0b10000000,
                0b10000000,
                0b10000000,
                0b10000000,
                0b01111111,
                0b00000000,
            },
        ['D'] =
            {
                0b11111100,
                0b10000010,
                0b10000001,
                0b10000001,
                0b10000001,
                0b10000010,
                0b11111100,
                0b00000000,
            },
        ['E'] =
            {
                0b11111111,
                0b10000000,
                0b10000000,
                0b11111111,
                0b10000000,
                0b10000000,
                0b11111111,
                0b00000000,
            },
        ['F'] =
            {
                0b11111111,
                0b10000000,
                0b10000000,
                0b11111100,
                0b10000000,
                0b10000000,
                0b10000000,
                0b00000000,
            },
        ['G'] =
            {
                0b01111111,
                0b10000000,
                0b10000000,
                0b10011111,
                0b10000001,
                0b10000001,
                0b01111111,
                0b00000000,
            },
        ['H'] =
            {
                0b10000001,
                0b10000001,
                0b10000001,
                0b11111111,
                0b10000001,
                0b10000001,
                0b10000001,
                0b00000000,
            },
        ['I'] =
            {
                0b11111111,
                0b00001000,
                0b00001000,
                0b00001000,
                0b00001000,
                0b00001000,
                0b11111111,
                0b00000000,
            },
        ['J'] =
            {
                0b11111111,
                0b00000100,
                0b00000100,
                0b00000100,
                0b10000100,
                0b10000100,
                0b01111000,
                0b00000000,
            },
        ['K'] =
            {
                0b10000011,
                0b10001100,
                0b10110000,
                0b11000000,
                0b10110000,
                0b10001100,
                0b10000011,
                0b00000000,
            },
        ['L'] =
            {
                0b10000000,
                0b10000000,
                0b10000000,
                0b10000000,
                0b10000000,
                0b10000000,
                0b11111111,
                0b00000000,
            },
        ['M'] =
            {
                0b10000001,
                0b11000011,
                0b10100101,
                0b10011001,
                0b10011001,
                0b10000001,
                0b10000001,
                0b00000000,
            },
        ['N'] =
            {
                0b10000001,
                0b11000001,
                0b10100001,
                0b10010001,
                0b10001001,
                0b10000101,
                0b10000011,
                0b00000000,
            },
        ['O'] =
            {
                0b01111110,
                0b10000001,
                0b10000001,
                0b10000001,
                0b10000001,
                0b10000001,
                0b01111110,
                0b00000000,
            },
        ['P'] =
            {
                0b11111110,
                0b10000001,
                0b10000001,
                0b11111110,
                0b10000000,
                0b10000000,
                0b10000000,
                0b00000000,
            },
        ['Q'] =
            {
                0b01111110,
                0b10000001,
                0b10000001,
                0b10001001,
                0b10000101,
                0b10000010,
                0b01111101,
                0b00000000,
            },
        ['R'] =
            {
                0b11111110,
                0b10000001,
                0b10000011,
                0b11111100,
                0b10000010,
                0b10000001,
                0b10000001,
                0b00000000,
            },
        ['S'] =
            {
                0b01111111,
                0b10000000,
                0b01000000,
                0b00111100,
                0b00000010,
                0b00000001,
                0b11111110,
                0b00000000,
            },
        ['T'] =
            {
                0b11111111,
                0b00010000,
                0b00010000,
                0b00010000,
                0b00010000,
                0b00010000,
                0b00010000,
                0b00000000,
            },
        ['U'] =
            {
                0b10000001,
                0b10000001,
                0b10000001,
                0b10000001,
                0b10000001,
                0b01000010,
                0b00111100,
                0b00000000,
            },
        ['V'] =
            {
                0b10000001,
                0b10000001,
                0b01000010,
                0b01000010,
                0b00100100,
                0b00100100,
                0b00011000,
                0b00000000,
            },
        ['W'] =
            {
                0b10000001,
                0b10000001,
                0b10011001,
                0b10011001,
                0b10011001,
                0b01011010,
                0b01100110,
                0b00000000,
            },
        ['X'] =
            {
                0b10000001,
                0b01000010,
                0b00100100,
                0b00011000,
                0b00011000,
                0b00100100,
                0b11000011,
                0b00000000,
            },
        ['Y'] =
            {
                0b10000001,
                0b10000001,
                0b01000010,
                0b00100100,
                0b00011000,
                0b00011000,
                0b00011000,
                0b00000000,
            },
        ['Z'] =
            {
                0b11111111,
                0b00000010,
                0b00000100,
                0b00001000,
                0b00010000,
                0b00100000,
                0b11111111,
                0b00000000,
            },
        ['!'] =
            {
                0b00011000,
                0b00011000,
                0b00011000,
                0b00011000,
                0b00000000,
                0b00011000,
                0b00011000,
                0b00000000,
            },
        ['"'] =
            {
                0b01100110,
                0b01100110,
                0b01100110,
                0b00000000,
                0b00000000,
                0b00000000,
                0b00000000,
                0b00000000,
            },
        ['#'] =
            {
                0b00000000,
                0b00100100,
                0b11111111,
                0b00100100,
                0b00100100,
                0b11111111,
                0b00100100,
                0b00000000,
            },
        ['$'] =
            {
                0b00011000,
                0b01111111,
                0b10011000,
                0b01111110,
                0b00011001,
                0b11111110,
                0b00011000,
                0b00000000,
            },
        ['%'] =
            {
                0b00000000,
                0b01100010,
                0b01100100,
                0b00001000,
                0b00010000,
                0b00100110,
                0b01000110,
                0b00000000,
            },
        ['&'] =
            {
                0b00011000,
                0b00101000,
                0b00110000,
                0b01001011,
                0b10000100,
                0b10001010,
                0b01110001,
                0b00000000,
            },
        ['\''] =
            {
                0b00011000,
                0b00011000,
                0b00011000,
                0b00000000,
                0b00000000,
                0b00000000,
                0b00000000,
                0b00000000,
            },
        ['('] =
            {
                0b00000110,
                0b00011000,
                0b00100000,
                0b00100000,
                0b00100000,
                0b00011000,
                0b00000110,
                0b00000000,
            },
        [')'] =
            {
                0b01100000,
                0b00011000,
                0b00000100,
                0b00000100,
                0b00000100,
                0b00011000,
                0b01100000,
                0b00000000,
            },
        ['*'] =
            {
                0b00011000,
                0b01111110,
                0b00111100,
                0b01100110,
                0b00000000,
                0b00000000,
                0b00000000,
                0b00000000,
            },
        ['+'] =
            {
                0b00000000,
                0b00011000,
                0b00011000,
                0b01111110,
                0b01111110,
                0b00011000,
                0b00011000,
                0b00000000,
            },
        [','] =
            {
                0b00000000,
                0b00000000,
                0b00000000,
                0b00000000,
                0b00011000,
                0b00001000,
                0b00010000,
                0b00000000,
            },
        ['-'] =
            {
                0b00000000,
                0b00000000,
                0b00000000,
                0b01111110,
                0b00000000,
                0b00000000,
                0b00000000,
                0b00000000,
            },
        ['.'] =
            {
                0b00000000,
                0b00000000,
                0b00000000,
                0b00000000,
                0b00000000,
                0b00011000,
                0b00011000,
                0b00000000,
            },
        ['/'] =
            {
                0b00000000,
                0b00000010,
                0b00000100,
                0b00001000,
                0b00010000,
                0b00100000,
                0b01000000,
                0b00000000,
            },
        ['0'] =
            {
                0b01111110,
                0b10000001,
                0b10000011,
                0b10111101,
                0b11000001,
                0b10000001,
                0b01111110,
                0b00000000,
            },
        ['1'] =
            {
                0b00001000,
                0b00011000,
                0b00101000,
                0b00001000,
                0b00001000,
                0b00001000,
                0b11111111,
                0b00000000,
            },
        ['2'] =
            {
                0b01111110,
                0b10000001,
                0b00000001,
                0b00001110,
                0b01110000,
                0b10000000,
                0b11111111,
                0b00000000,
            },
        ['3'] =
            {
                0b11111110,
                0b00000001,
                0b00000001,
                0b01111110,
                0b00000001,
                0b00000001,
                0b11111110,
                0b00000000,
            },
        ['4'] =
            {
                0b10000001,
                0b10000001,
                0b10000001,
                0b01111111,
                0b00000001,
                0b00000001,
                0b00000001,
                0b00000000,
            },
        ['5'] =
            {
                0b11111111,
                0b10000000,
                0b10000000,
                0b11111100,
                0b00000010,
                0b00000001,
                0b11111110,
                0b00000000,
            },
        ['6'] =
            {
                0b00011111,
                0b01100000,
                0b10000000,
                0b11111110,
                0b10000001,
                0b10000001,
                0b01111110,
                0b00000000,
            },
        ['7'] =
            {
                0b11111111,
                0b00000001,
                0b00000010,
                0b00000100,
                0b00001000,
                0b00010000,
                0b00100000,
                0b00000000,
            },
        ['8'] =
            {
                0b01111110,
                0b10000001,
                0b10000001,
                0b01111110,
                0b10000001,
                0b10000001,
                0b01111110,
                0b00000000,
            },
        ['9'] =
            {
                0b01111110,
                0b10000001,
                0b10000001,
                0b01111111,
                0b00000001,
                0b00000001,
                0b00000001,
                0b00000000,
            },
        [':'] =
            {
                0b00000000,
                0b00011000,
                0b00011000,
                0b00000000,
                0b00011000,
                0b00011000,
                0b00000000,
                0b00000000,
            },
        [';'] =
            {
                0b00000000,
                0b00011000,
                0b00011000,
                0b00000000,
                0b00011000,
                0b00001000,
                0b00010000,
                0b00000000,
            },
        ['<'] =
            {
                0b00000011,
                0b00001100,
                0b00110000,
                0b11000000,
                0b00110000,
                0b00001100,
                0b00000011,
                0b00000000,
            },
        ['='] =
            {
                0b00000000,
                0b00000000,
                0b11111111,
                0b00000000,
                0b11111111,
                0b00000000,
                0b00000000,
                0b00000000,
            },
        ['>'] =
            {
                0b11000000,
                0b00110000,
                0b00001100,
                0b00000011,
                0b00001100,
                0b00110000,
                0b11000000,
                0b00000000,
            },
        ['?'] =
            {
                0b01111110,
                0b10000001,
                0b00000110,
                0b00011000,
                0b00000000,
                0b00011000,
                0b00000000,
            },
        ['@'] =
            {
                0b01111110,
                0b10000001,
                0b10011111,
                0b10100001,
                0b10011110,
                0b10000000,
                0b01111110,
                0b00000000,
            },
        ['['] =
            {
                0b00111100,
                0b00100000,
                0b00100000,
                0b00100000,
                0b00100000,
                0b00100000,
                0b00111100,
                0b00000000,
            },
        ['\\'] =
            {
                0b00000000,
                0b01000000,
                0b00100000,
                0b00010000,
                0b00001000,
                0b00000100,
                0b00000010,
                0b00000000,
            },
        [']'] =
            {
                0b00111100,
                0b00000100,
                0b00000100,
                0b00000100,
                0b00000100,
                0b00000100,
                0b00111100,
                0b00000000,
            },
        ['^'] =
            {
                0b00011000,
                0b00100100,
                0b01000010,
                0b00000000,
                0b00000000,
                0b00000000,
                0b00000000,
                0b00000000,
            },
        ['_'] =
            {
                0b00000000,
                0b00000000,
                0b00000000,
                0b00000000,
                0b00000000,
                0b00000000,
                0b11111111,
                0b00000000,
            },
        ['`'] =
            {
                0b01100000,
                0b00010000,
                0b00001100,
                0b00000000,
                0b00000000,
                0b00000000,
                0b00000000,
                0b00000000,
            },
        ['{'] =
            {
                0b00000110,
                0b00011000,
                0b00100000,
                0b00011000,
                0b00100000,
                0b00011000,
                0b00000110,
                0b00000000,
            },
        ['|'] =
            {
                0b00011000,
                0b00011000,
                0b00011000,
                0b00011000,
                0b00011000,
                0b00011000,
                0b00011000,
                0b00000000,
            },
        ['}'] =
            {
                0b01100000,
                0b00011000,
                0b00000100,
                0b00011000,
                0b00000100,
                0b00011000,
                0b01100000,
                0b00000000,
            },
        ['~'] =
            {
                0b00000000,
                0b00000000,
                0b01100001,
                0b10010001,
                0b10001110,
                0b00000000,
                0b00000000,
                0b00000000,
            },
        [' '] =
            {
                0b00000000,
                0b00000000,
                0b00000000,
                0b00000000,
                0b00000000,
                0b00000000,
                0b00000000,
                0b00000000,
            },
};
