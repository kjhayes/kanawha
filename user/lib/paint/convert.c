
#include <paint/paint.h>
#include <kanawha/gfx.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

ssize_t
paint_gfx_format_pixel_size(
        unsigned long format)
{
    switch(format)
    {
    case GFX_FORMAT_MONO8:
    case GFX_FORMAT_BYTE_R1G1B1I1:
    case GFX_FORMAT_BYTE_R3G3B2:
    case GFX_FORMAT_ASCII:
    case GFX_FORMAT_VGA_CHAR:
    case GFX_FORMAT_VGA_ATTR:
        return 1;
    case GFX_FORMAT_MONO16:
        return 2;
    case GFX_FORMAT_MONO32:
    case GFX_FORMAT_RGBA32:
    case GFX_FORMAT_RBGA32:
    case GFX_FORMAT_GRBA32:
    case GFX_FORMAT_GBRA32:
    case GFX_FORMAT_BRGA32:
    case GFX_FORMAT_BGRA32:
        return 4;
    case GFX_FORMAT_MONO64:
        return 8;
    default:
        return -ENXIO;
    }
}

static int
paint_convert_pixel_to_rgba(
        unsigned long format,
        void *data,
        uint32_t *rgba_out)
{
    uint8_t tmp_byte;
    uint8_t r = 0;
    uint8_t g = 0;
    uint8_t b = 0;
    uint8_t a = 0;
    switch(format)
    {
    case GFX_FORMAT_RGBA32:
        *(uint32_t *)rgba_out = *(uint32_t *)data;
        return 0;
    case GFX_FORMAT_RBGA32:
        r = ((uint8_t *)data)[0];
        b = ((uint8_t *)data)[1];
        g = ((uint8_t *)data)[2];
        a = ((uint8_t *)data)[3];
        break;
    case GFX_FORMAT_BRGA32:
        b = ((uint8_t *)data)[0];
        r = ((uint8_t *)data)[1];
        g = ((uint8_t *)data)[2];
        a = ((uint8_t *)data)[3];
        break;
    case GFX_FORMAT_BGRA32:
        b = ((uint8_t *)data)[0];
        g = ((uint8_t *)data)[1];
        r = ((uint8_t *)data)[2];
        a = ((uint8_t *)data)[3];
        break;
    case GFX_FORMAT_GBRA32:
        g = ((uint8_t *)data)[0];
        b = ((uint8_t *)data)[1];
        r = ((uint8_t *)data)[2];
        a = ((uint8_t *)data)[3];
        break;
    case GFX_FORMAT_GRBA32:
        g = ((uint8_t *)data)[0];
        r = ((uint8_t *)data)[1];
        b = ((uint8_t *)data)[2];
        a = ((uint8_t *)data)[3];
        break;
    case GFX_FORMAT_BYTE_R1G1B1I1:
        tmp_byte = *(uint8_t *)data;
        r = ((tmp_byte >> 0) & 1);
        g = ((tmp_byte >> 1) & 1);
        b = ((tmp_byte >> 2) & 1);
        tmp_byte = ((tmp_byte >> 3) & 1) ? 0xFF : 0x80;
        r *= tmp_byte;
        g *= tmp_byte;
        b *= tmp_byte;
        a = 0xFF;
        break;
    case GFX_FORMAT_VGA_ATTR:
        tmp_byte = *(uint8_t *)data >> 4;
        r = ((tmp_byte >> 0) & 1);
        g = ((tmp_byte >> 1) & 1);
        b = ((tmp_byte >> 2) & 1);
        tmp_byte = ((tmp_byte >> 3) & 1) ? 0xFF : 0x80;
        r *= tmp_byte;
        g *= tmp_byte;
        b *= tmp_byte;
        a = 0xFF;
        break;
    case GFX_FORMAT_ASCII:
    case GFX_FORMAT_VGA_CHAR:
        tmp_byte = *(uint8_t *)data;
        if(isgraph(tmp_byte) && (tmp_byte != ' '))
        {
            r = 0xB0;
            g = 0xB0;
            b = 0xB0;
            a = 0xFF;
        }
        else
        {
            r = 0x00;
            g = 0x00;
            b = 0x00;
            a = 0x00;
        }
        break;
    default:
        return -EINVAL;
    }

    *(uint32_t *)rgba_out =
        r | ((uint32_t)g << 8) | ((uint32_t)b << 16) | ((uint32_t)a << 24);

    return 0;
}

static int
paint_convert_pixel_from_rgba(
        uint32_t rgba,
        unsigned long format,
        void *to_data)
{
    uint8_t tmp_byte;
    uint8_t *rgba_bytes = (uint8_t *)&rgba;
    uint32_t r = rgba_bytes[0];
    uint32_t g = rgba_bytes[1];
    uint32_t b = rgba_bytes[2];
    uint32_t a = rgba_bytes[3];

    switch(format)
    {
    case GFX_FORMAT_RGBA32:
        *(uint32_t *)to_data = rgba;
        return 0;
    case GFX_FORMAT_RBGA32:
        *(uint32_t *)to_data = r | (b << 8) | (g << 16) | (a << 24);
        return 0;
    case GFX_FORMAT_BRGA32:
        *(uint32_t *)to_data = b | (r << 8) | (g << 16) | (a << 24);
        return 0;
    case GFX_FORMAT_BGRA32:
        *(uint32_t *)to_data = b | (g << 8) | (r << 16) | (a << 24);
        return 0;
    case GFX_FORMAT_GBRA32:
        *(uint32_t *)to_data = g | (b << 8) | (r << 16) | (a << 24);
        return 0;
    case GFX_FORMAT_GRBA32:
        *(uint32_t *)to_data = g | (r << 8) | (b << 16) | (a << 24);
        return 0;
    case GFX_FORMAT_MONO8:
        *(uint8_t *)to_data = (r + b + g) / 3;
        return 0;
    case GFX_FORMAT_MONO16:
        *(uint16_t *)to_data = ((r + b + g) / 3) << 8;
        return 0;
    case GFX_FORMAT_MONO32:
        *(uint32_t *)to_data = ((r + b + g) / 3) << 24;
        return 0;
    case GFX_FORMAT_MONO64:
        *(uint64_t *)to_data = (uint64_t)((r + b + g) / 3) << 56;
        return 0;
    default:
        break;
    }

    uint8_t avg = (r + b + g) / 3;
    switch(format)
    {
    case GFX_FORMAT_BYTE_R1G1B1I1:
        *(uint8_t *)to_data = (r >= 0x60) | ((g >= 0x60) << 1) |
                              ((b >= 0x60) << 2) | ((avg >= 0x80) << 3);
        return 0;
    case GFX_FORMAT_BYTE_R3G3B2:
        *(uint8_t *)to_data = (((r >> 5) & 0b111) << 0) |
                              (((g >> 5) & 0b111) << 3) |
                              (((b >> 6) & 0b011) << 6);
        return 0;
    case GFX_FORMAT_VGA_CHAR:
    case GFX_FORMAT_ASCII:
    {
        char c;
        if(avg > 0xC0)
        {
            c = '@';
        }
        else if(avg > 0x80)
        {
            c = '#';
        }
        else if(avg > 0x40)
        {
            c = '*';
        }
        else if(avg > 0x20)
        {
            c = '.';
        }
        else
        {
            c = ' ';
        }
        *(uint8_t *)to_data = c;
    }
        return 0;
    case GFX_FORMAT_VGA_ATTR:
        tmp_byte = ((r >= 0x80) | ((g >= 0x80) << 1) | ((b >= 0x80) << 2) |
                    ((avg >= 0xF0) << 3))
                   << 4;
        tmp_byte |= ((r >= 0x40) | ((g >= 0x40) << 1) | ((b >= 0x40) << 2) |
                     ((avg >= 0xA0) << 3));
        *(uint8_t *)to_data = tmp_byte;
        return 0;
    default:
        break;
    }

    return -ENXIO;
}

int
paint_convert_pixel(
        unsigned long to_format,
        void *to_data,
        unsigned long from_format,
        void *from_data)
{
    int res;

    // Special case if the formats are the same
    if(to_format == from_format) {
        ssize_t len = paint_gfx_format_pixel_size(to_format);
        if(len < 0) {
            //fprintf(stderr, "paint: trying to convert invalid format %lu!\n", to_format);
            return len;
        }
        memcpy(to_data, from_data, len);
        return 0;
    }

    switch(to_format) {
        case GFX_FORMAT_RGBA32:
            //fprintf(stderr, "paint: converting from %lu to rgba!\n", from_format);
            return paint_convert_pixel_to_rgba(
                    from_format,
                    from_data,
                    to_data);
        default:
            break;
    }

    switch(from_format) {
        case GFX_FORMAT_RGBA32:
            //fprintf(stderr, "paint: converting to %lu from rgba!\n", to_format);
            return paint_convert_pixel_from_rgba(
                    *(uint32_t*)from_data,
                    to_format,
                    to_data);
        default:
            break;
    }

    // Try using RGBA as a lingua franca
    do {
        uint32_t rgba;
        res = paint_convert_pixel_to_rgba(
                from_format,
                from_data,
                &rgba);
        if(res) {
            break;
        }

        res = paint_convert_pixel_from_rgba(
                rgba,
                to_format,
                to_data);
        if(res) {
            break;
        }

        return 0;
    } while(0);

    //fprintf(stderr, "paint: failed to convert %lu to %lu!\n", from_format, to_format);
    return -EINVAL;
}

