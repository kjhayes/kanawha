
#include <drivers/fb/vga/vga.h>
#include <drivers/vga/vga.h>
#include <kanawha/dev/fb.h>
#include <kanawha/endian.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/page_alloc.h>
#include <kanawha/string.h>

extern struct vga_fb_mode vga_fb_mode_text_80_25;
extern struct vga_fb_mode vga_fb_mode_text_80_50;
extern struct vga_fb_mode vga_fb_mode_text_132_50;
extern struct vga_fb_mode vga_fb_mode_graphics_320_200;
extern struct vga_fb_mode vga_fb_mode_graphics_640_480;

static struct vga_fb_mode *vga_fb_modes[] = {
    &vga_fb_mode_text_80_25,
    &vga_fb_mode_text_80_50,
    &vga_fb_mode_text_132_50,
    &vga_fb_mode_graphics_320_200,
    &vga_fb_mode_graphics_640_480,
};
#define VGA_FB_NUM_MODES (sizeof(vga_fb_modes) / sizeof(*vga_fb_modes))

#define VGA_FB_DEFAULT_MODE (3)

// Must be called with the mode lock held
static int
__vga_fb_set_buffer_size(struct vga_fb *fb, size_t size)
{
    int res;

    if(size == 0)
    {
        return -EINVAL;
    }

    order_t new_buffer_order = 64 - __builtin_clzl(size);
    void __phys *new_buffer;
    res = page_alloc(new_buffer_order, &new_buffer, 0);
    if(res)
    {
        return res;
    }

    if(fb->buffer_exists)
    {
        res = page_free(fb->buffer_order, fb->buffer);
        if(res)
        {
            page_free(new_buffer_order, new_buffer);
            return res;
        }
    }

    fb->buffer = new_buffer;
    fb->buffer_order = new_buffer_order;
    fb->buffer_exists = 1;

    // Clear the buffer
    memset_p(fb->buffer, 0, 1ULL << fb->buffer_order);

    return 0;
}

#define VGA_FB_BASE_ADDR (void __phys *)0xA0000

static struct fb_mode_info *
vga_fb_get_mode_info(struct fb_dev *dev, size_t index)
{
    struct vga_fb *fb = container_of(dev, struct vga_fb, fb_dev);

    if(index >= VGA_FB_NUM_MODES)
    {
        return NULL;
    }

    return vga_fb_modes[index]->mode_info;
}

static int
vga_fb_put_mode_info(struct fb_dev *dev, size_t index)
{
    struct vga_fb *fb = container_of(dev, struct vga_fb, fb_dev);

    if(index >= VGA_FB_NUM_MODES)
    {
        return -EINVAL;
    }

    return 0;
}

static int
vga_fb_set_mode(struct fb_dev *dev, size_t index)
{
    struct vga_fb *fb = container_of(dev, struct vga_fb, fb_dev);

    if(index >= VGA_FB_NUM_MODES)
    {
        return -ENXIO;
    }

    int res;
    thread_lock_acquire(&fb->mode_lock);

    struct vga_fb_mode *mode = vga_fb_modes[index];

    res = __vga_fb_set_buffer_size(fb, mode->mode_info->buffer_size);
    if(res)
    {
        thread_lock_release(&fb->mode_lock);
        return res;
    }

    // Clear all of video memory
    vga_write_field(fb->vga_dev, WriteMode, 0);
    vga_write_field(fb->vga_dev, HostOddEvenMemoryWriteAddressingDisable, 1);
    vga_write_field(fb->vga_dev, ChainOddEvenEnable, 0);
    vga_write_field(fb->vga_dev, Chain4Enable, 0);
    vga_write_field(fb->vga_dev, MemoryPlaneWriteEnable, 0b1111);
    vga_write_field(fb->vga_dev, ExtendedMemory, 1);
    vga_write_field(fb->vga_dev, RAMEnable, 1);
    vga_write_field(fb->vga_dev, MemoryMapSelect, 1);
    vga_write_field(fb->vga_dev, BitMask, 0xFF);
    vga_write_field(fb->vga_dev, EnableSetReset, 0);
    vga_write_field(fb->vga_dev, SetReset, 0);
    vga_write_field(fb->vga_dev, LogicalOperation, 0);
    vga_write_field(fb->vga_dev, RotateCount, 0);
    memset_p((void __phys *)0xA0000, 0x0, 0x10000);

    res = (mode->setup)(fb);
    if(res)
    {
        thread_lock_release(&fb->mode_lock);
        return res;
    }

    fb->current_mode = index;

    thread_lock_release(&fb->mode_lock);
    return res;
}

static ssize_t
vga_fb_get_mode(struct fb_dev *dev)
{
    struct vga_fb *fb = container_of(dev, struct vga_fb, fb_dev);

    return fb->current_mode;
}

static int
vga_fb_load_buffer(struct fb_dev *dev, void __phys **base_out)
{
    int res;
    struct vga_fb *fb = container_of(dev, struct vga_fb, fb_dev);

    size_t buffer_size;

    thread_lock_acquire(&fb->mode_lock);

    DEBUG_ASSERT(fb->buffer_exists);

    *base_out = fb->buffer;

    thread_lock_release(&fb->mode_lock);
    return 0;
}
static int
vga_fb_unload_buffer(struct fb_dev *dev, void __phys *base_out)
{
    struct vga_fb *fb = container_of(dev, struct vga_fb, fb_dev);

    int res;

    // Don't need to do anything, we allocate and deallocate the buffer on mode
    // switch

    return 0;
}

static int
vga_fb_flush_buffer(struct fb_dev *dev)
{
    int res;
    struct vga_fb *fb = container_of(dev, struct vga_fb, fb_dev);

    thread_lock_acquire(&fb->mode_lock);

    if(!fb->buffer_exists)
    {
        thread_lock_release(&fb->mode_lock);
        return 0;
    }

    if(fb->current_mode >= VGA_FB_NUM_MODES)
    {
        thread_lock_release(&fb->mode_lock);
        return -EINVAL;
    }

    struct vga_fb_mode *mode = vga_fb_modes[fb->current_mode];

    // Wait for VSYNC for a maximum of 10ms
    duration_t max_vsync_wait = msec_to_duration(10);
    time_t start = current_timestamp();
    while(!vga_read_field(fb->vga_dev, VerticalRetrace))
    {
        duration_t elapsed = duration_between(start, current_timestamp());
        if(elapsed < 0 || elapsed >= max_vsync_wait)
        {
            break;
        }
    }

    res = (*mode->flush)(fb);

    thread_lock_release(&fb->mode_lock);
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
vga_fb_probe_vga_dev(struct vga_dev *dev)
{
    return 0;
}

static int
vga_fb_receive_vga_dev(struct vga_dev *dev)
{
    int res;

    struct vga_fb *fb = kzmalloc(sizeof(struct vga_fb), KM_KERNEL);
    if(fb == NULL)
    {
        return -ENOMEM;
    }

    fb->vga_dev = dev;
    dev->registry_node.owner_priv_data = fb;

    thread_lock_init(&fb->mode_lock);
    fb->buffer_exists = 0;
    fb->current_mode = 0;
    res = vga_fb_set_mode(&fb->fb_dev, VGA_FB_DEFAULT_MODE);
    if(res)
    {
        kfree(fb);
        return res;
    }

    fb->fb_dev.driver = &vga_fb_driver;

    res = register_fb_dev(&fb->fb_dev, "vga");
    if(res)
    {
        eprintk("register_fb_dev returned %s\n", errnostr(res));
        kfree(fb);
        return res;
    }

    return 0;
}

static int
vga_fb_revoke_vga_dev(struct vga_dev *dev)
{
    int res;
    struct vga_fb *fb = dev->registry_node.owner_priv_data;
    res = unregister_fb_dev(&fb->fb_dev);
    if(res)
    {
        return res;
    }
    if(fb->buffer_exists)
    {
        res = page_free(fb->buffer_order, fb->buffer);
        if(res)
        {
            eprintk("Failed to free VGA framebuffer backing page! "
                    "(err=%s)\n",
                    errnostr(res));
        }
    }
    kfree(fb);
    return 0;
}

static struct vga_dev_owner vga_fb_vga_dev_owner = {
    .probe = vga_fb_probe_vga_dev,
    .receive = vga_fb_receive_vga_dev,
    .revoke = vga_fb_revoke_vga_dev,
};

static int
vga_fb_install_vga_dev_owner(void)
{
    int res;
    res = register_vga_dev_owner(&vga_fb_vga_dev_owner);
    if(res)
    {
        return res;
    }
    return 0;
}
declare_init(device, vga_fb_install_vga_dev_owner);
