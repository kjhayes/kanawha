
#include <kanawha/gfx/convert.h>
#include <kanawha/gfx/layout.h>
#include <kanawha/errno.h>
#include <kanawha/string.h>
#include <kanawha/assert.h>
#include <kanawha/stddef.h>

// Use FB_FORMAT_RGBA as a "lingua franca"
static inline int
gfx_convert_to_rgba(
        unsigned long format,
        void *data,
	size_t bitoffset,
        uint8_t *rgba_out)
{
    uint8_t r = 0;
    uint8_t g = 0;
    uint8_t b = 0;
    uint8_t a = 0;
    switch(format) {
        case GFX_FORMAT_RGBA32:
            *(uint32_t*)rgba_out = *(uint32_t*)data;
            return 0;
        case GFX_FORMAT_RBGA32:
            r = ((uint8_t*)data)[0];
            b = ((uint8_t*)data)[1];
            g = ((uint8_t*)data)[2];
            a = ((uint8_t*)data)[3];
            break;
        case GFX_FORMAT_BRGA32:
            b = ((uint8_t*)data)[0];
            r = ((uint8_t*)data)[1];
            g = ((uint8_t*)data)[2];
            a = ((uint8_t*)data)[3];
            break;
        case GFX_FORMAT_BGRA32:
            b = ((uint8_t*)data)[0];
            g = ((uint8_t*)data)[1];
            r = ((uint8_t*)data)[2];
            a = ((uint8_t*)data)[3];
            break;
        case GFX_FORMAT_GBRA32:
            g = ((uint8_t*)data)[0];
            b = ((uint8_t*)data)[1];
            r = ((uint8_t*)data)[2];
            a = ((uint8_t*)data)[3];
            break;
        case GFX_FORMAT_GRBA32:
            g = ((uint8_t*)data)[0];
            r = ((uint8_t*)data)[1];
            b = ((uint8_t*)data)[2];
            a = ((uint8_t*)data)[3];
            break;
	case GFX_FORMAT_BIT_MONO:
	    if((*(uint8_t*)data >> bitoffset) & 0b1) {
		*(uint32_t*)rgba_out = 0xFFFFFFFFUL;
	    } else {
		*(uint32_t*)rgba_out = 0x0;
	    }
	    return 0;
        default:
            return -EINVAL;
    }

    *(uint32_t*)rgba_out = r | ((uint32_t)g << 8) | ((uint32_t)b << 16) | ((uint32_t)a << 24);

    return 0;
}

static inline int
gfx_convert_from_rgba(
        uint32_t *rgba,
        unsigned long to_format,
        void *to_data,
	size_t bitoffset)
{
    uint8_t *rgba_bytes = (uint8_t*)rgba;
    uint32_t r = rgba_bytes[0];
    uint32_t g = rgba_bytes[1];
    uint32_t b = rgba_bytes[2];
    uint32_t a = rgba_bytes[3];
    size_t tmp_index;

    switch(to_format) {
        case GFX_FORMAT_RGBA32:
            *(uint32_t*)to_data = *(uint32_t*)rgba;
            return 0;
        case GFX_FORMAT_RBGA32:
            *(uint32_t*)to_data = r | (b<<8) | (g<<16) | (a<<24);
            return 0;
        case GFX_FORMAT_BRGA32:
            *(uint32_t*)to_data = b | (r<<8) | (g<<16) | (a<<24);
            return 0;
        case GFX_FORMAT_BGRA32:
            *(uint32_t*)to_data = b | (g<<8) | (r<<16) | (a<<24);
            return 0;
        case GFX_FORMAT_GBRA32:
            *(uint32_t*)to_data = g | (b<<8) | (r<<16) | (a<<24);
            return 0;
        case GFX_FORMAT_GRBA32:
            *(uint32_t*)to_data = g | (r<<8) | (b<<16) | (a<<24);
            return 0;
        default:
            break;
    }

    uint8_t avg = (r + g + b)/3;
    switch(to_format) {
        case GFX_FORMAT_BYTE_R1G1B1I1:
            *(uint8_t*)to_data =
                   (r >= 0x80)
                | ((g >= 0x80)<<1)
                | ((b >= 0x80)<<2)
                | ((avg >= 0x60 || r > 0xC0 || g > 0xC0 || b > 0xC0) << 3);
            return 0;
        case GFX_FORMAT_BYTE_R3G3B2:
            *(uint8_t*)to_data =
                    (((r >> 5) & 0b111) << 0)
                  | (((g >> 5) & 0b111) << 3)
                  | (((b >> 6) & 0b011) << 6);
            return 0;
        case GFX_FORMAT_VGA_ATTR:
            *(uint8_t*)to_data =
                  ((r >= 0x60)
                | ((g >= 0x60)<<1)
                | ((b >= 0x60)<<2)
                | ((avg >= 0x80)<<3)) << 4;
            return 0;
        case GFX_FORMAT_MONO8:
            *(uint8_t*)to_data = avg;
            return 0;
        case GFX_FORMAT_MONO16:
            *(uint16_t*)to_data = ((uint16_t)avg) << 8;
            return 0;
        case GFX_FORMAT_MONO32:
            *(uint32_t*)to_data = ((uint32_t)avg) << 24;
            return 0;
        case GFX_FORMAT_MONO64:
            *(uint64_t*)to_data = ((uint64_t)avg) << 56;
            return 0;
        case GFX_FORMAT_VGA_CHAR:
        case GFX_FORMAT_ASCII:
	    if(avg > 0x80) {
		*(uint8_t*)to_data = '#';
	    } else {
		*(uint8_t*)to_data = ' ';
	    }
            return 0;
	case GFX_FORMAT_BIT_MONO:
	    if(avg > 0x80) {
		*(uint8_t*)to_data |= (1<<bitoffset);
	    } else {
		*(uint8_t*)to_data &= ~(1<<bitoffset);
	    }
	    return 0;
        default:
            break;
    }

    return -EINVAL;
}

static inline int
gfx_convert_pixel(
        unsigned long from_format,
        void *from_data,
	size_t from_bitoffset,
        unsigned long to_format,
        void *to_data,
	size_t to_bitoffset)
{
    uint32_t rgba;

    int res = gfx_convert_to_rgba(
            from_format,
            from_data,
	    from_bitoffset,
            (uint8_t*)&rgba);
    if(res) {
        return res;
    }

    res = gfx_convert_from_rgba(
            &rgba,
            to_format,
            to_data,
	    to_bitoffset);
    if(res) {
        return res;
    }
    return 0;
}

int
gfx_convert(
	struct gfx_layout *in_layout,
	void *in_buf,
	size_t in_buflen,
	struct gfx_layout *out_layout,
	void *out_buf,
	size_t out_buflen)
{
    int res;

    int in_bitwise = gfx_format_is_bitwise(in_layout->format);
    int out_bitwise = gfx_format_is_bitwise(out_layout->format);

    size_t in_bitstride = in_layout->stride;
    size_t in_bitoffset = in_layout->offset;
    if(!in_bitwise) {
	in_bitstride *= 8;
	in_bitoffset *= 8;
    }
    size_t out_bitstride = out_layout->stride;
    size_t out_bitoffset = out_layout->offset;
    if(!out_bitwise) {
	out_bitstride *= 8;
	out_bitoffset *= 8;
    }

    for(size_t y = 0; y < out_layout->height; y++) {
        for(size_t x = 0; x < out_layout->width; x++) {
	    size_t out_index;
	    switch(out_layout->order) {
		case GFX_ORDER_ROW_MAJOR:
		    out_index = x + (y * out_layout->width);
		    break;
		case GFX_ORDER_COLUMN_MAJOR:
		    out_index = y + (x * out_layout->height);
		    break;
		default:
		    return -EINVAL;
	    }

	    size_t in_x = (x * in_layout->width) / out_layout->width;
	    size_t in_y = (y * in_layout->height) / out_layout->height;

	    size_t in_index;
	    switch(in_layout->order) {
		case GFX_ORDER_ROW_MAJOR:
		    in_index = in_x + (in_y * in_layout->width);
		    break;
		case GFX_ORDER_COLUMN_MAJOR:
		    in_index = in_y + (in_x * in_layout->height);
		    break;
		default:
		    return -EINVAL;
	    }

	    size_t in_total_bitoffset = ((in_index * in_bitstride) + in_bitoffset);
	    size_t in_byte_offset = in_total_bitoffset / 8;
	    size_t in_bit_offset = in_total_bitoffset % 8;
	    size_t out_total_bitoffset = ((out_index * out_bitstride) + out_bitoffset);
	    size_t out_byte_offset = out_total_bitoffset / 8;
	    size_t out_bit_offset = out_total_bitoffset % 8;

            res = gfx_convert_pixel(
                    in_layout->format,
                    in_buf + in_byte_offset,
            	    in_bit_offset,
                    out_layout->format,
                    out_buf + out_byte_offset,
            	    out_bit_offset);
	    if(res) {
		return res;
	    }
        }
    }

#ifdef CONFIG_DEBUGGING
    if(
      in_layout->format == out_layout->format &&
      in_layout->order == out_layout->order &&
      in_layout->width == out_layout->width &&
      in_layout->height == out_layout->height &&
      in_layout->offset == out_layout->offset &&
      in_layout->stride == out_layout->stride
      )
    {
	size_t minlen = MIN(in_buflen, out_buflen);
	DEBUG_ASSERT(memcmp(in_buf, out_buf, minlen) == 0);
    }
#endif

    return 0;
}

