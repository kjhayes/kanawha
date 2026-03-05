#ifndef __CABIN_FBTERM__COLOR_H__
#define __CABIN_FBTERM__COLOR_H__

#include <stdint.h>

typedef struct color
{
    union
    {
        struct
        {
            uint8_t r;
            uint8_t g;
            uint8_t b;
            uint8_t a;
        } __attribute__((packed));
        uint32_t data;
    } __attribute__((packed));
} color_t;

#endif
