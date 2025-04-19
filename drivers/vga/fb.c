
#include <kanawha/fb_dev.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/spinlock.h>
#include <kanawha/page_alloc.h>
#include <kanawha/endian.h>
#include <drivers/vga/vga.h>

struct vga_fb
{
    struct fb_dev fb_dev;
    struct vga_dev vga_dev;

    spinlock_t mode_lock;
    size_t current_mode;
    int buffer_exists;
    void __phys *buffer;
    order_t buffer_order;
};

// Must be called with the mode lock held
static int
__vga_fb_set_buffer_size(
        struct vga_fb *fb,
        size_t size)
{
    int res;

    if(size == 0) {
        return -EINVAL;
    }

    order_t new_buffer_order = 64 - __builtin_clzl(size);
    void __phys *new_buffer;
    res = page_alloc(new_buffer_order, &new_buffer, 0);
    if(res) {
        return res;
    }

    if(fb->buffer_exists) {
        res = page_free(fb->buffer_order, fb->buffer);
        if(res) {
            page_free(new_buffer_order, new_buffer);
            return res;
        }
    }

    fb->buffer = new_buffer;
    fb->buffer_order = new_buffer_order;
    fb->buffer_exists = 1;

    // Clear the buffer
    memset(__va(fb->buffer), 0, 1ULL<<fb->buffer_order);

    return 0;
}

#define VGA_FB_BASE_ADDR (void __phys *)0xA0000

static struct fb_mode_info vga_fb_mode_0 =
{
    .buffer_size = 80*25*2,
    .layer_count = 2,
    .layer_infos = {
        {
            .format = FB_LAYER_FORMAT_VGA_CHAR,
            .order = FB_LAYER_ORDER_ROW_MAJOR,
            .width = 80,
            .height = 25,
            .offset = 0,
            .stride = 2,
        },
        {
            .format = FB_LAYER_FORMAT_VGA_ATTR,
            .order = FB_LAYER_ORDER_ROW_MAJOR,
            .width = 80,
            .height = 25,
            .offset = 0,
            .stride = 2,
        },
    },
};

static int
vga_fb_flush_mode_0(
        struct vga_fb *fb)
{
    void *vga_mem = __va((void __phys *)0xA0000);
    void *buffer = __va(fb->buffer);
    vga_screen_disable(&fb->vga_dev);
    memcpy(vga_mem, buffer, 80*25*2);
    vga_screen_enable(&fb->vga_dev);
    return 0;
}

static int
vga_fb_set_mode_0(
        struct vga_fb *fb)
{
    int res;
    struct vga_dev *vga = &fb->vga_dev;

    // Allocate the buffer
    res = __vga_fb_set_buffer_size(fb, 80*25*2);
    if(res) {
        spin_unlock(&fb->mode_lock);
        return res;
    }

    fb->current_mode = 0;

    vga_screen_disable(vga);

//    vga_set_write_mode(vga, 0);
//    vga_set_write_planes(vga, 0b1111);
//    vga_set_read_mode(vga, 0);
//    vga_set_alphanumeric(vga, 1);
//    vga_set_horizontal_panning(vga, 8);

    // TODO: Load a font

    vga_screen_enable(vga);

    res = vga_fb_flush_mode_0(fb);
    if(res) {
        wprintk("Failed to flush VGA framebuffer after mode-setting (err=%s)!\n",
                errnostr(res));
    }

    return 0;
}

static struct fb_mode_info vga_fb_mode_1 =
{
    .buffer_size = 320 * 200,
    .layer_count = 1,
    .layer_infos = {
    {
        .format = FB_LAYER_FORMAT_BYTE_R3G3B2,
        .order = FB_LAYER_ORDER_ROW_MAJOR,
        .width = 320,
        .height = 200,
        .offset = 0,
        .stride = 1,
    },
    },
};

static int
vga_fb_flush_mode_1(
        struct vga_fb *fb)
{
    void *vga_mem = __va((void __phys *)0xA0000);
    void *buffer = __va(fb->buffer);
    vga_screen_disable(&fb->vga_dev);
    memcpy(vga_mem, buffer, 320 * 200);
    vga_screen_enable(&fb->vga_dev);
    return 0;
}

static int
vga_fb_set_mode_1(
        struct vga_fb *fb)
{
    int res;
    struct vga_dev *vga = &fb->vga_dev;

    res = __vga_fb_set_buffer_size(fb, 320*200);
    if(res) {
        return res;
    }

    fb->current_mode = 1;

    vga_screen_disable(vga);

    vga_enable_linear(vga);
    vga_disable_even_odd(vga);
    vga_set_write_mode(vga, 0);
    vga_set_write_planes(vga, 0b1111);
    vga_set_color_planes(vga, 0b1111);
    vga_set_read_mode(vga, 0);
    vga_set_alphanumeric(vga, 0);
    vga_set_color_mode_pop_4(vga);
    vga_enable_8_bit_color(vga);
    vga_set_horizontal_panning(vga, 0);
    vga_disable_half_rate_dot_clock(vga);
    vga_enable_8_dot_mode(vga);

    vga_unlock_crt_reg(vga);

    vga_crt_disable_retrace(vga);

    // Because we are using 256 color mode, we need to double the "horizontal resolution" our timings are targeting
    static const uint16_t effective_hres = 320;
    static const uint16_t effective_vres = 200;
    static const uint16_t hblank = 32;
    static const uint16_t vblank = 32;
    vga_crt_set_horizontal_total(vga, ((effective_hres + hblank) * 2) / vga_get_dots_per_character(vga));
    vga_crt_set_vertical_total(vga, (effective_vres + vblank));

    vga_crt_set_horizontal_display_end(vga, (effective_hres * 2) / vga_get_dots_per_character(vga));
    vga_crt_set_vertical_display_end(vga, effective_vres);

    vga_crt_set_horizontal_blanking_start(vga, (effective_hres * 2) / vga_get_dots_per_character(vga));
    vga_crt_set_horizontal_blanking_end(vga, (hblank * 2) / vga_get_dots_per_character(vga));

    vga_crt_set_vertical_blanking_start(vga, effective_vres);
    vga_crt_set_vertical_blanking_end(vga, vblank);
   
    vga_crt_disable_scan_doubling(vga);
    vga_crt_set_maximum_scanline(vga, 0);
    vga_crt_set_address_size(vga, 4);
    vga_crt_set_scanline_offset(
            vga,
            (320*2)/8 // "address" length of a scanline
            );
    vga_lock_crt_reg(vga);

    // TODO Remove this (it's just here for debugging)
    uint8_t *mem = __va(fb->buffer);
    for(size_t y = 0; y < 200; y++) {
        memset(mem + (y * 320), (uint8_t)y, 320);
    }

    for(int i = 0; i < 256; i++) {
        uint8_t value = i;
        uint8_t r = ((value >> 0) & 0b111) << 3;
        uint8_t g = ((value >> 3) & 0b111) << 3;
        uint8_t b = ((value >> 6) & 0b11) << 4;
        vga_dac_set_color(vga, i, r, g, b);
    }

    vga_fb_flush_mode_1(fb);

    vga_screen_enable(vga);

    return 0;
}

#define VGA_FB_MODE_2_HRES 640
#define VGA_FB_MODE_2_VRES 400
static struct fb_mode_info vga_fb_mode_2 =
{
    .buffer_size = VGA_FB_MODE_2_HRES * VGA_FB_MODE_2_VRES,
    .layer_count = 1,
    .layer_infos = {
    {
        .format = FB_LAYER_FORMAT_BYTE_R1G1B1I1,
        .order = FB_LAYER_ORDER_ROW_MAJOR,
        .width = VGA_FB_MODE_2_HRES,
        .height = VGA_FB_MODE_2_VRES,
        .offset = 0,
        .stride = 1,
    },
    },
};

static int
vga_fb_flush_mode_2(
        struct vga_fb *fb)
{
    uint8_t *vga_mem = __va((void __phys *)0xA0000);
    uint8_t *buffer = __va(fb->buffer);
    vga_screen_disable(&fb->vga_dev);
    for(int shift = 0; shift < 4; shift++) {
        vga_set_write_planes(&fb->vga_dev, 1<<shift);
        for(size_t i = 0; i < vga_fb_mode_2.buffer_size/8; i++) {
            uint8_t *pixels = &buffer[i*8];
            uint8_t data = 0;
            for(int bit = 0; bit < 8; bit++) {
                data <<= 1;
                data |= (pixels[bit] >> shift) & 0b1;
            }
//            if(data != 0x0) {
//                printk("Writing: 0x%x to plane %d offset=0x%x\n",
//                    data, shift, i);
//            }
            vga_mem[i] = data;
        }
    }
    vga_set_write_planes(&fb->vga_dev, 0b0000);
    vga_screen_enable(&fb->vga_dev);
    return 0;
}

static int
vga_fb_set_mode_2(
        struct vga_fb *fb)
{
    int res;
    struct vga_dev *vga = &fb->vga_dev;

    res = __vga_fb_set_buffer_size(fb, vga_fb_mode_2.buffer_size);
    if(res) {
        return res;
    }

    fb->current_mode = 2;

    vga_screen_disable(vga);

    vga_enable_planar(vga);
    vga_disable_even_odd(vga);

    vga_set_write_mode(vga, 0);
    vga_set_write_planes(vga, 0b0);
    vga_set_color_planes(vga, 0b1111);

    vga_set_read_mode(vga, 0);
    vga_set_alphanumeric(vga, 0);

    vga_set_color_mode_pop_1(vga);
    vga_disable_8_bit_color(vga);

    vga_set_horizontal_panning(vga, 0);
    vga_disable_half_rate_dot_clock(vga);
    vga_enable_8_dot_mode(vga);

    vga_unlock_crt_reg(vga);

    vga_crt_disable_retrace(vga);

    // Because we are using 256 color mode, we need to double the "horizontal resolution" our timings are targeting
    static const uint16_t effective_hres = VGA_FB_MODE_2_HRES;
    static const uint16_t effective_vres = VGA_FB_MODE_2_VRES;
    static const uint16_t hblank = 32;
    static const uint16_t vblank = 32;
    vga_crt_set_horizontal_total(vga, (effective_hres + hblank) / vga_get_dots_per_character(vga));
    vga_crt_set_vertical_total(vga, (effective_vres + vblank));

    vga_crt_set_horizontal_display_end(vga, effective_hres / vga_get_dots_per_character(vga));
    vga_crt_set_vertical_display_end(vga, effective_vres);

    vga_crt_set_horizontal_blanking_start(vga, effective_hres / vga_get_dots_per_character(vga));
    vga_crt_set_horizontal_blanking_end(vga, hblank / vga_get_dots_per_character(vga));

    vga_crt_set_vertical_blanking_start(vga, effective_vres);
    vga_crt_set_vertical_blanking_end(vga, vblank);
    
    vga_crt_disable_scan_doubling(vga);
    vga_crt_set_maximum_scanline(vga, 0);
    vga_crt_set_address_size(vga, 4);
    vga_crt_set_scanline_offset(
            vga,
            VGA_FB_MODE_2_HRES/(4*2) // "address" length of a scanline
            );

    vga_lock_crt_reg(vga);

    for(uint8_t index = 0; index < 16; index++) {
        uint16_t r = (index>>0) & 0b1;
        uint16_t g = (index>>1) & 0b1;
        uint16_t b = (index>>2) & 0b1;
        uint16_t i = (index>>3) & 0b1;
        r *= i ? 0b111111 : 0b011111;
        g *= i ? 0b111111 : 0b011111;
        b *= i ? 0b111111 : 0b011111;
        vga_dac_set_color(vga, index, r, g, b);
    }

    vga_fb_flush_mode_2(fb);

    vga_screen_enable(vga);

    return 0;
}

static struct fb_mode_info *
vga_fb_get_mode_info(
        struct fb_dev *dev,
        size_t index)
{
    struct vga_fb *fb =
        container_of(dev, struct vga_fb, fb_dev);

    switch(index) {
        case 0:
            return &vga_fb_mode_0;
        case 1:
            return &vga_fb_mode_1;
        case 2:
            return &vga_fb_mode_2;
        default:
            return NULL;
    }
}
static int
vga_fb_put_mode_info(
        struct fb_dev *dev,
        size_t index)
{
    struct vga_fb *fb =
        container_of(dev, struct vga_fb, fb_dev);

    switch(index) {
        case 0:
        case 1:
            return 0;
        default:
            return -EINVAL;
    }
}
static int
vga_fb_set_mode(
        struct fb_dev *dev,
        size_t index)
{
    struct vga_fb *fb =
        container_of(dev, struct vga_fb, fb_dev);

    int res;
    spin_lock(&fb->mode_lock);
    switch(index) {
      case 0:
        res = vga_fb_set_mode_0(fb);
        break;
      case 1:
        res = vga_fb_set_mode_1(fb);
        break;
      case 2:
        res = vga_fb_set_mode_2(fb);
        break;
      default:
        res = -EINVAL;
        break;
    }
    spin_unlock(&fb->mode_lock);
    return res;
}

static ssize_t
vga_fb_get_mode(
        struct fb_dev *dev)
{
    struct vga_fb *fb =
        container_of(dev, struct vga_fb, fb_dev);

    return fb->current_mode;
}

static int
vga_fb_load_buffer(
        struct fb_dev *dev,
        void __phys ** base_out)
{
    int res;
    struct vga_fb *fb =
        container_of(dev, struct vga_fb, fb_dev);

    size_t buffer_size;

    spin_lock(&fb->mode_lock);

    DEBUG_ASSERT(fb->buffer_exists);

    *base_out = fb->buffer;

    spin_unlock(&fb->mode_lock);
    return 0;
}
static int
vga_fb_unload_buffer(
        struct fb_dev *dev,
        void __phys * base_out)
{
    struct vga_fb *fb =
        container_of(dev, struct vga_fb, fb_dev);

    int res;

    spin_lock(&fb->mode_lock);

    DEBUG_ASSERT(fb->buffer_exists);

    // Don't need to do anything, we allocate and deallocate the buffer on mode switch

    spin_unlock(&fb->mode_lock);

    return 0;
}

static int
vga_fb_flush_buffer(
        struct fb_dev *dev)
{
    int res;
    struct vga_fb *fb =
        container_of(dev, struct vga_fb, fb_dev);

    spin_lock(&fb->mode_lock);

    if(!fb->buffer_exists) {
        spin_unlock(&fb->mode_lock);
        return 0;
    }

    switch(fb->current_mode) {
        case 0:
            res = vga_fb_flush_mode_0(fb);
            break;
        case 1:
            res = vga_fb_flush_mode_1(fb);
            break;
        case 2:
            res = vga_fb_flush_mode_2(fb);
            break;
        default:
            res = -EINVAL;
    }

    spin_unlock(&fb->mode_lock);
    return res;
}

static struct fb_driver vga_fb_driver = {
    .set_mode = vga_fb_set_mode,
    .get_mode = vga_fb_get_mode,
    .get_mode_info = vga_fb_get_mode_info,
    .put_mode_info = vga_fb_put_mode_info,
    .load_buffer = vga_fb_load_buffer,
    .unload_buffer = vga_fb_unload_buffer,
    .flush_buffer = vga_fb_flush_buffer,
};

static int
register_vga_fb_dev(void)
{
    int res;

    struct vga_fb *fb = kmalloc(sizeof(struct vga_fb));
    if(fb == NULL) {
        return -ENOMEM;
    }
    memset(fb, 0, sizeof(struct vga_fb));

    res = vga_dev_init(&fb->vga_dev, &default_vga_ports);
    if(res) {
        kfree(fb);
        return res;
    }

    spinlock_init(&fb->mode_lock);
    fb->buffer_exists = 0;
    fb->current_mode = 0;
    res = vga_fb_set_mode_0(fb);
    if(res) {
        kfree(fb);
        return res;
    }

    res = register_fb_dev(
            &fb->fb_dev,
            "vga",
            &vga_fb_driver);
    if(res) {
        printk("register_fb_dev returned %s\n",
                errnostr(res));
        kfree(fb);
        return res;
    }

    return 0;
}

declare_init_desc(device, register_vga_fb_dev, "Registering VGA Framebuffer Device");
