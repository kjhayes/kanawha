
#include <drivers/fb/virtio_gpu.h>
#include <drivers/virtio/driver.h>
#include <drivers/virtio/queue.h>
#include <drivers/virtio/request.h>
#include <drivers/virtio/virtio.h>
#include <kanawha/dev/fb.h>
#include <kanawha/id.h>
#include <kanawha/init.h>
#include <kanawha/irq.h>
#include <kanawha/kmalloc.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>

DEFINE_LOCAL_ID_RANGE(virtio_gpu_id_range, 0);

static struct fb_mode_info virtio_gpu_mode_0_info = {
    .buffer_size = 640 * 480 * 4,
    .layer_count = 1,
    .layer_infos =
        {
            {
                .layout =
                    {
                        .format = GFX_FORMAT_RGBA32,
                        .order = GFX_ORDER_ROW_MAJOR,
                        .width = 640,
                        .height = 480,
                        .offset = 0,
                        .stride = 4,
                    },
            },
        },
};

static struct fb_mode_info *virtio_gpu_mode_list[] = {
    &virtio_gpu_mode_0_info,
};

#define VIRTIO_GPU_MODE_COUNT                                                  \
    (sizeof(virtio_gpu_mode_list) / sizeof(struct fb_mode_info *))

static struct fb_mode_info *
virtio_gpu_fb_get_mode_info(struct fb_dev *dev, size_t index)
{
    dprintk("virtio_gpu_fb_get_mode_info\n");
    if(index < VIRTIO_GPU_MODE_COUNT)
    {
        return virtio_gpu_mode_list[index];
    }
    return NULL;
}
static int
virtio_gpu_fb_put_mode_info(struct fb_dev *dev, size_t index)
{
    dprintk("virtio_gpu_fb_put_mode_info\n");
    return 0;
}
static int
virtio_gpu_fb_set_mode(struct fb_dev *dev, size_t index)
{
    dprintk("virtio_gpu_fb_set_mode\n");

    struct virtio_gpu *gpu = container_of(dev, struct virtio_gpu, fb_dev);

    if(index >= VIRTIO_GPU_MODE_COUNT)
    {
        return -ENXIO;
    }

    gpu->current_mode = index;

    return 0;
}

static ssize_t
virtio_gpu_fb_get_mode(struct fb_dev *dev)
{
    dprintk("virtio_gpu_fb_get_mode\n");

    struct virtio_gpu *gpu = container_of(dev, struct virtio_gpu, fb_dev);

    return gpu->current_mode;
}

static int
virtio_gpu_fb_load_buffer(struct fb_dev *dev, void __phys **base_out)
{
    int res;

    dprintk("virtio_gpu_fb_load_buffer\n");

    struct virtio_gpu *gpu = container_of(dev, struct virtio_gpu, fb_dev);

    struct fb_mode_info *mode_info = virtio_gpu_mode_list[gpu->current_mode];
    size_t buffer_size = mode_info->buffer_size;

    if(mode_info->layer_count != 1)
    {
        eprintk("virtio_gpu_fb_load_buffer: called with invalid mode!\n");
        return -EINVAL;
    }

    enum virtio_gpu_formats gpu_format;
    switch(mode_info->layer_infos[0].layout.format)
    {
    case GFX_FORMAT_RGBA32:
        gpu_format = VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM;
        break;
    // TODO other cases
    default:
        eprintk("virtio_gpu_fb_load_buffer: called with invalid mode!\n");
        return -EINVAL;
    }

    // Allocate the physical memory

    res = dma_alloc(buffer_size, 12, 0, &gpu->current_buffer);
    if(res)
    {
        wprintk("virtio_gpu_fb_load_buffer: failed to allocate frame "
                "buffer!\n");
        return res;
    }

    gpu->current_buffer_size = buffer_size;
    void *framebuffer = dma_virt_addr(gpu->current_buffer);
    memset(framebuffer, 0, buffer_size);

    dprintk("creating resource...\n");
    gpu->current_res =
        virtio_gpu_create_resource_2d(gpu,
                                      mode_info->layer_infos[0].layout.width,
                                      mode_info->layer_infos[0].layout.height,
                                      gpu_format);
    if(gpu->current_res == NULL)
    {
        dma_free(gpu->current_buffer, buffer_size);
        wprintk("virtio_gpu_fb_load_buffer: failed to create 2D resource!\n");
        return res;
    }

    dprintk("attaching backing...\n");
    res = virtio_gpu_resource_attach_backing(gpu->current_res,
                                             dma_phys_addr(gpu->current_buffer),
                                             gpu->current_buffer_size);
    if(res)
    {
        dma_free(gpu->current_buffer, buffer_size);
        virtio_gpu_destroy_resource_2d(gpu->current_res);
        gpu->current_res = NULL;
        wprintk("virtio_gpu_fb_load_buffer: failed to attach backing to 2D "
                "resource!\n");
        return res;
    }

    dprintk("setting up scanouts...\n");
    for(size_t i = 0; i < gpu->num_scanouts; i++)
    {
        struct virtio_gpu_scanout *scanout = &gpu->scanouts[i];
        if(scanout->enabled)
        {
            res =
                virtio_gpu_set_scanout(gpu,
                                       i,
                                       mode_info->layer_infos[0].layout.width,
                                       mode_info->layer_infos[0].layout.height,
                                       gpu->current_res);
            if(res)
            {
                wprintk("virtio_gpu_fb_load_buffer: failed to "
                        "set scanout!\n");
                dma_free(gpu->current_buffer, buffer_size);
                virtio_gpu_destroy_resource_2d(gpu->current_res);
                gpu->current_res = NULL;
                return res;
            }
        }
    }

    res = virtio_gpu_resource_transfer_to_host(gpu->current_res);
    if(res)
    {
        wprintk("virtio_gpu_fb_load_buffer: failed to transfer "
                "framebuffer!\n");
    }

    res = virtio_gpu_resource_flush(gpu->current_res);
    if(res)
    {
        wprintk("virtio_gpu_fb_load_buffer: failed to flush framebuffer!\n");
    }

    *base_out = dma_phys_addr(gpu->current_buffer);

    printk("virtio_gpu_fb_load_buffer success!\n");
    return 0;
}

static int
virtio_gpu_fb_unload_buffer(struct fb_dev *dev, void __phys *base_out)
{
    int res;

    struct virtio_gpu *gpu = container_of(dev, struct virtio_gpu, fb_dev);

    res = virtio_gpu_destroy_resource_2d(gpu->current_res);
    if(res)
    {
        return res;
    }
    gpu->current_res = NULL;

    dma_free(gpu->current_buffer, gpu->current_buffer_size);

    return 0;
}

static int
virtio_gpu_fb_flush_buffer(struct fb_dev *dev)
{
    int res;

    dprintk("virtio_gpu_fb_flush_buffer\n");

    struct virtio_gpu *gpu = container_of(dev, struct virtio_gpu, fb_dev);

    if(gpu->current_res == NULL)
    {
        wprintk("virtio_gpu_fb_flush_buffer without a current resource!\n");
        return 0;
    }

    res = virtio_gpu_resource_transfer_to_host(gpu->current_res);
    if(res)
    {
        wprintk("virtio_gpu_fb_flush_buffer: transfer to host failed "
                "(err=%s)!\n",
                errnostr(res));
        return res;
    }

    res = virtio_gpu_resource_flush(gpu->current_res);
    if(res)
    {
        wprintk("virtio_gpu_fb_flush_buffer: resource flush failed "
                "(err=%s)!\n",
                errnostr(res));
        return res;
    }

    return 0;
}

static struct fb_driver virtio_gpu_fb_driver = {
    .set_mode = virtio_gpu_fb_set_mode,
    .get_mode = virtio_gpu_fb_get_mode,
    .get_mode_info = virtio_gpu_fb_get_mode_info,
    .put_mode_info = virtio_gpu_fb_put_mode_info,
    .load_buffer = virtio_gpu_fb_load_buffer,
    .unload_buffer = virtio_gpu_fb_unload_buffer,
    .flush_buffer = virtio_gpu_fb_flush_buffer,
};

static int
virtio_gpu_probe(struct virtio_driver *driver, struct virtio_device *device)
{
    dprintk("virtio_gpu_probe\n");
    return 0;
}

static int
virtio_gpu_negotiate(struct virtio_driver *driver, struct virtio_device *device)
{
    dprintk("virtio_gpu_negotiate\n");
    return 0;
}

static int
virtio_gpu_init_device(struct virtio_driver *driver,
                       struct virtio_device *device)
{
    int res;

    dprintk("virtio_gpu_init_device\n");

    if(device->num_queues != 2)
    {
        return -EINVAL;
    }

    struct virtio_gpu *gpu = kzmalloc(sizeof(struct virtio_gpu), KM_KERNEL);
    if(gpu == NULL)
    {
        return -ENOMEM;
    }

    spinlock_init(&gpu->resource_lock);
    ptree_init(&gpu->resource_tree);

    gpu->control_queue = device->queues[0];
    if(gpu->control_queue == NULL)
    {
        kfree(gpu);
        return -EINVAL;
    }

    gpu->cursor_queue = device->queues[1];
    if(gpu->cursor_queue == NULL)
    {
        kfree(gpu);
        return -EINVAL;
    }

    res = virtio_queue_enable(gpu->control_queue);
    if(res)
    {
        kfree(gpu);
        return res;
    }

    res = virtio_queue_enable(gpu->cursor_queue);
    if(res)
    {
        virtio_queue_disable(gpu->control_queue);
        kfree(gpu);
        return res;
    }

    res = virtio_gpu_update_scanout_info(gpu);
    if(res)
    {
        virtio_queue_disable(gpu->control_queue);
        virtio_queue_disable(gpu->cursor_queue);
        return res;
    }

    dprintk("virtio-gpu has %d active scanouts!\n", gpu->num_enabled_scanouts);
    for(size_t i = 0; i < gpu->num_scanouts; i++)
    {
        struct virtio_gpu_scanout *scanout = &gpu->scanouts[i];
        if(scanout->enabled)
        {
            dprintk("scanout[%lu] x=0x%lx, y=0x%lx, width=0x%lx, "
                    "height=0x%lx\n",
                    (ul_t)i,
                    (ul_t)scanout->pref_pos_x,
                    (ul_t)scanout->pref_pos_y,
                    (ul_t)scanout->pref_width,
                    (ul_t)scanout->pref_height);
        }
    }

    unsigned long dev_index;
    dev_index = id_range_alloc(&virtio_gpu_id_range);

#define NAMEBUFLEN 64
    char namebuf[NAMEBUFLEN];
    snprintk(namebuf, NAMEBUFLEN, "virtio-gpu-%ld", dev_index);
    namebuf[NAMEBUFLEN - 1] = '\0';

    gpu->name = kstrdup(namebuf);
    if(gpu->name == NULL)
    {
        virtio_queue_disable(gpu->control_queue);
        virtio_queue_disable(gpu->cursor_queue);
        kfree(gpu);
        return res;
    }

    gpu->fb_dev.driver = &virtio_gpu_fb_driver;

    res = register_fb_dev(&gpu->fb_dev, gpu->name);
    if(res)
    {
        virtio_queue_disable(gpu->control_queue);
        virtio_queue_disable(gpu->cursor_queue);
        kfree(gpu->name);
        kfree(gpu);
        return res;
    }

    device->driver_priv = gpu;
    dprintk("virtio_gpu Initialized\n");

    return 0;
}

static int
virtio_gpu_deinit_device(struct virtio_driver *driver,
                         struct virtio_device *device)
{
    int res;

    struct virtio_gpu *gpu = device->driver_priv;

    res = unregister_fb_dev(&gpu->fb_dev);
    if(res) {
        return res;
    }

    virtio_queue_disable(gpu->control_queue);
    virtio_queue_disable(gpu->cursor_queue);

    kfree(gpu->name);
    kfree(gpu);

    return 0;
}

static struct virtio_driver_ops virtio_gpu_driver_ops = {
    .probe = virtio_gpu_probe,
    .negotiate = virtio_gpu_negotiate,
    .init_device = virtio_gpu_init_device,
    .deinit_device = virtio_gpu_deinit_device,
};

static uint16_t virtio_gpu_virtio_ids[] = {
    16,
};

static struct virtio_driver virtio_gpu_driver = {
    .ops = &virtio_gpu_driver_ops,
    .num_ids = sizeof(virtio_gpu_virtio_ids) / sizeof(uint16_t),
    .ids = virtio_gpu_virtio_ids,
};

static int
register_virtio_gpu_driver(void)
{
    return register_virtio_driver(&virtio_gpu_driver);
}
declare_init_desc(device,
                  register_virtio_gpu_driver,
                  "Registered Virtio GPU Driver");
