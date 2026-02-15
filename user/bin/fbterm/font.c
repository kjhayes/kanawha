
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "font.h"

#define GLYPH_FORMAT GFX_FORMAT_RGBA32

struct psf_1_header {
    uint8_t magic[2];
    uint8_t flags;
    uint8_t glyph_size;
};

struct font_data *
load_font(const char *path)
{
    FILE *file = fopen(path, "r");
    if(file == NULL) {
        return NULL;
    }

    struct psf_1_header psf_1_header;
    size_t read = fread(&psf_1_header, sizeof(struct psf_1_header), 1, file);
    if(read != 1) {
        fclose(file);
        return NULL;
    }

    if(psf_1_header.magic[0] != 0x36 ||
       psf_1_header.magic[1] != 0x04)
    {
        fclose(file);
        return NULL;
    }

    size_t font_data_size = psf_1_header.glyph_size * 256;
    uint8_t *font_data = malloc(font_data_size);
    if(font_data == NULL) {
        fclose(file);
        return NULL;
    }

    read = fread(font_data, font_data_size, 1, file);
    if(read != 1) {
        free(font_data);
        fclose(file);
        return NULL;
    }

    fclose(file);

    struct font_data *fdata = malloc(sizeof(struct font_data));
    if(fdata == NULL) {
        free(font_data);
        return NULL;
    }
    memset(fdata, 0, sizeof(struct font_data));

    fdata->width = 8;
    fdata->height = psf_1_header.glyph_size;
    fdata->num_glyphs = 256;

    fdata->glyphs = malloc(sizeof(struct glyph_data) * fdata->num_glyphs);
    if(fdata->glyphs == NULL) {
        free(font_data);
        free(fdata);
        return NULL;
    }
    memset(fdata->glyphs, 0, sizeof(struct image *) * fdata->num_glyphs);

    for(size_t i = 0; i < fdata->num_glyphs; i++) {
        struct kfb_image *fg_img = malloc(sizeof(struct kfb_image));
        struct kfb_image *bg_img = malloc(sizeof(struct kfb_image));
        color_t *fg_pixel_data = malloc(sizeof(color_t) * fdata->width * fdata->height);
        color_t *bg_pixel_data = malloc(sizeof(color_t) * fdata->width * fdata->height);

        if(fg_img == NULL || bg_img == NULL || fg_pixel_data == NULL || bg_pixel_data == NULL) {
            for(size_t fi = 0; fi < i; fi++) {
                free(fdata->glyphs[fi].fg->data);
                free(fdata->glyphs[fi].bg->data);
                free(fdata->glyphs[fi].fg);
                free(fdata->glyphs[fi].bg);
            }
            free(fdata->glyphs);
            free(fdata);
            free(font_data);
            free(fg_img);
            free(bg_img);
            free(fg_pixel_data);
            free(bg_pixel_data);
            return NULL;
        }

        fg_img->resx = fdata->width;
        fg_img->resy = fdata->height;
        fg_img->data = (void*)fg_pixel_data;
        fg_img->format = GLYPH_FORMAT;
        fg_img->order = GFX_ORDER_ROW_MAJOR;
        fg_img->stride = sizeof(color_t);
        fg_img->offset = 0;
        fg_img->data_size = fg_img->resx * fg_img->resy * sizeof(color_t);

        bg_img->resx = fdata->width;
        bg_img->resy = fdata->height;
        bg_img->data = (void*)bg_pixel_data;
        bg_img->format = GLYPH_FORMAT;
        bg_img->order = GFX_ORDER_ROW_MAJOR;
        bg_img->stride = sizeof(color_t);
        bg_img->offset = 0;
        bg_img->data_size = bg_img->resx * bg_img->resy * sizeof(color_t);

        // Render the image
        uint8_t *glyph = font_data + (i * fdata->height);
        for(size_t fy = 0; fy < fdata->height; fy++) {
            uint8_t bits = glyph[fy];
            for(int fx = 0; fx < 8; fx++) {
                int value = (bits >> (7-fx)) & 1;
                color_t *fg_pixel = &((color_t*)fg_img->data)[fx + (fy*fdata->width)];
                color_t *bg_pixel = &((color_t*)bg_img->data)[fx + (fy*fdata->width)];
                if(value) {
                    fg_pixel->r = 0xFF;
                    fg_pixel->g = 0xFF;
                    fg_pixel->b = 0xFF;
                    fg_pixel->a = 0xFF;
                    bg_pixel->r = 0x00;
                    bg_pixel->g = 0x00;
                    bg_pixel->b = 0x00;
                    bg_pixel->a = 0x00;
                } else {
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

    free(font_data);

    return fdata;
}

void
unload_font(struct font_data *fdata)
{
    for(size_t i = 0; i < fdata->num_glyphs; i++) {
        free(fdata->glyphs[i].fg->data);
        free(fdata->glyphs[i].bg->data);
        free(fdata->glyphs[i].fg);
        free(fdata->glyphs[i].bg);
    }
    free(fdata->glyphs);
    free(fdata);
}

