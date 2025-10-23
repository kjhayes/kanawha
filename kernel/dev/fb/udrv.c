
#include <kanawha/init.h>
#include <kanawha/dev/fb.h>
#include <kanawha/kmalloc.h>
#include <kanawha/udrv.h>
#include <kanawha/atomic.h>
#include <kanawha/dma.h>
#include <kanawha/uapi/udrv/fb.h>
#include <kanawha/uapi/file.h>

static struct fb_driver udrv_fb_driver;

struct udrv_fb_dev_mode_info {
    ilist_node_t list_node;
    size_t index;
    atomic_t refs;
    struct fb_mode_info mode_info;
};

static inline void
udrv_fb_dev_mode_info_get_ref(
	struct udrv_fb_dev_mode_info *info)
{
    __maybe_unused atomic_val_t old;
    old = atomic_fetch_inc(&info->refs);
    DEBUG_ASSERT(old > 0);
}

static inline void
udrv_fb_dev_mode_info_put_ref(
	struct udrv_fb_dev_mode_info *info)
{
    atomic_val_t old = atomic_fetch_dec(&info->refs);
    DEBUG_ASSERT(old >= 1);
    if(old == 1) {
	// Destroy the object
	kfree(info);
    }
}

struct udrv_fb_dev
{
    struct udrv_dev udrv_dev;
    struct fb_dev fb_dev;

    irq_lock_t mode_lock;
    ilist_t mode_info_list;
    struct udrv_fb_dev_mode_info *current_mode;

    size_t buffer_size;
    dma_addr_t buffer;
    
    char *name;
};

static int __udrv_fb_set_mode_lockless(struct udrv_fb_dev *dev, size_t mode);

static struct udrv_dev *
fb_dev_udrv_create(
	struct udrv_mount *mnt,
	const char *name)
{
    int res;

    struct udrv_fb_dev *dev = kmalloc(sizeof(*dev), KM_KERNEL);
    if(dev == NULL) {
	return NULL;
    }

    dev->name = kstrdup(name);
    if(dev->name == NULL) {
	kfree(dev);
	return NULL;
    }

    irq_lock_init(&dev->mode_lock);
    dev->current_mode = NULL;
    ilist_init(&dev->mode_info_list);
    dev->buffer_size = 0;

    dev->fb_dev.driver = &udrv_fb_driver;
    res = register_fb_dev(&dev->fb_dev, dev->name);
    if(res) {
	kfree(dev->name);
	kfree(dev);
	return NULL;
    }

    return &dev->udrv_dev;
}

static int
fb_dev_udrv_destroy(
	struct udrv_mount *mnt,
	struct udrv_dev *udrv_dev)
{
    int res;

    struct udrv_fb_dev *dev = container_of(udrv_dev, struct udrv_fb_dev, udrv_dev);

    res = unregister_fb_dev(&dev->fb_dev);
    if(res) {
	return res;
    }

    kfree(dev->name);
    kfree(dev);

    return 0;
}

static int
fb_dev_udrv_have_mode_info(
	struct udrv_fb_dev *dev,
	unsigned long index)
{
    irq_lock_acquire(&dev->mode_lock);

    ilist_node_t *iter;
    ilist_for_each(iter, &dev->mode_info_list) {
	struct udrv_fb_dev_mode_info *cur =
	    container_of(iter, struct udrv_fb_dev_mode_info, list_node);
	if(cur->index == index) {
            irq_lock_release(&dev->mode_lock);
	    return 1;
	}
    }

    irq_lock_release(&dev->mode_lock);
    return 0;
}

static int
fb_dev_udrv_revoke_mode_info(
	struct udrv_fb_dev *dev,
	unsigned long index)
{
    irq_lock_acquire(&dev->mode_lock);

    ilist_node_t *iter;
    ilist_for_each(iter, &dev->mode_info_list) {
	struct udrv_fb_dev_mode_info *cur =
	    container_of(iter, struct udrv_fb_dev_mode_info, list_node);
	if(cur->index == index) {
	    // We need to remove this node
	    ilist_remove(&dev->mode_info_list, iter);
	    if(dev->current_mode == cur) {
	        udrv_fb_dev_mode_info_put_ref(dev->current_mode);
		dev->current_mode = NULL;
	    }
            irq_lock_release(&dev->mode_lock);

	    udrv_fb_dev_mode_info_put_ref(cur);

	    return 0;
	}
    }

    irq_lock_release(&dev->mode_lock);
    return -ENXIO;
}

static int
fb_dev_udrv_add_mode_info(
	struct udrv_fb_dev *dev,
	unsigned long index,
	struct fb_mode_info *mode_info,
	size_t mode_info_len)
{
    struct udrv_fb_dev_mode_info *info;
    info = kmalloc(sizeof(struct udrv_fb_dev_mode_info) + mode_info_len, KM_KERNEL);
    if(info == NULL) {
	return -ENOMEM;
    }
    info->index = index;
    memcpy(&info->mode_info, mode_info, mode_info_len);
    atomic_set_relaxed(&info->refs, 1);

    // TODO: We need to verify that the actual mode info structure claims
    //       to be the right size (or less than the right size)

    irq_lock_acquire(&dev->mode_lock);
    ilist_push_tail(&dev->mode_info_list, &info->list_node);
    if(dev->current_mode == NULL) {
	__udrv_fb_set_mode_lockless(dev, index);
    }
    irq_lock_release(&dev->mode_lock);

    printk("Added mode info for udrv fb_dev: %s\n",
	    fb_dev_get_name(&dev->fb_dev));

    return 0;
}

static int
fb_dev_udrv_on_recv(
	struct udrv_mount *mnt,
	struct udrv_dev *udrv_dev,
	struct udrv_pkt *pkt,
	size_t pktlen)
{
    int res;

    struct udrv_fb_dev *dev = container_of(udrv_dev, struct udrv_fb_dev, udrv_dev);
    struct fb_dev *fb = &dev->fb_dev;
    size_t datalen = pktlen - sizeof(struct udrv_pkt);

    switch(pkt->type) {
	case UDRV_FB_PKT_PROVIDE_MODE_INFO:
	{
	    if(datalen < sizeof(struct udrv_fb_pkt_provide_mode_info)) {
		return -EINVAL;
	    }

	    size_t mode_info_len = datalen
		-(sizeof(struct udrv_fb_pkt_provide_mode_info)
		- sizeof(struct fb_mode_info));

	    if(mode_info_len < sizeof(struct fb_mode_info)) {
		return -EINVAL;
	    }

	    struct udrv_fb_pkt_provide_mode_info *args = (void*)pkt->data;
	    struct fb_mode_info *mode_info = &args->mode_info;

	    size_t layer_count = mode_info->layer_count;
	    size_t layer_datalen = sizeof(struct fb_layer_info) * layer_count;

	    if(mode_info_len < (layer_datalen + sizeof(struct fb_mode_info))) {
		return -EINVAL;
	    }

	    unsigned long index = args->index;
	    if(fb_dev_udrv_have_mode_info(dev, index)) {
		res = fb_dev_udrv_revoke_mode_info(dev, index);
		if(res) {
		    return res;
		}
	    }

	    res = fb_dev_udrv_add_mode_info(
		    dev,
		    index,
		    &args->mode_info,
		    mode_info_len);
	    if(res) {
		return res;
	    }

	    return 0;
	}
	case UDRV_FB_PKT_REVOKE_MODE_INFO:
	{
	    if(datalen < sizeof(struct udrv_fb_pkt_revoke_mode_info)) {
		return -EINVAL;
	    }

	    struct udrv_fb_pkt_revoke_mode_info *args = (void*)pkt->data;
	    unsigned long index = args->index;
	    res = fb_dev_udrv_revoke_mode_info(dev, index); 
	    if(res) {
		return res;
	    }
	    return 0;
	}
	default:
	    wprintk("udrv: fb_dev Received invalid packet! (type=%ld)\n",
		    (sl_t)pkt->type);
	    return -EINVAL;
    }
}

static struct udrv_mount_ops
fb_dev_udrv_mount_ops = {
    .create = fb_dev_udrv_create,
    .destroy = fb_dev_udrv_destroy,
    .on_recv = fb_dev_udrv_on_recv,
};

static struct udrv_mount
fb_dev_udrv_mount = {
    .ops = &fb_dev_udrv_mount_ops,
};

static int
register_fb_dev_udrv(void)
{
    int res;
    res = register_udrv_mount(&fb_dev_udrv_mount, "fb");
    if(res) {
	return res;
    }
    return 0;
}
declare_init_desc(fs, register_fb_dev_udrv, "Registering fb_dev Userspace Driver Framework");

static ssize_t
udrv_fb_get_mode(struct fb_dev *fb_dev)
{
    ssize_t mode;
    struct udrv_fb_dev *dev = container_of(fb_dev, struct udrv_fb_dev, fb_dev);
    irq_lock_acquire(&dev->mode_lock);
    if(dev->current_mode != NULL) {
	mode = dev->current_mode->index;
    } else {
	mode = -EINVAL;
    }
    irq_lock_release(&dev->mode_lock);
    return mode;
}

static int
__udrv_fb_set_mode_lockless(
        struct udrv_fb_dev *dev,
	size_t mode)
{
    if(dev->current_mode != NULL && dev->current_mode->index == mode) {
	// No change, just return 0
	return 0;
    }

    if(dev->buffer_size > 0) {
	// We cannot change modes when the buffer is loaded
	return -EINVAL;
    }

    // Find the new mode
    struct udrv_fb_dev_mode_info *new_mode = NULL;
    {
        ilist_node_t *iter;
	ilist_for_each(iter, &dev->mode_info_list) {
	    struct udrv_fb_dev_mode_info *cur
		= container_of(iter, struct udrv_fb_dev_mode_info, list_node);
	    if(cur->index == mode) {
		new_mode = cur;
		break;
	    }
	}
    }
    if(new_mode == NULL) {
	// The requested mode does not exist
	return -ENXIO;
    }

    // Notify userspace of the new mode
    struct udrv_pkt *req_pkt
	= udrv_create_user_pkt(sizeof(*req_pkt)
		             + sizeof(struct udrv_fb_pkt_set_mode));
    struct udrv_fb_pkt_set_mode *set_mode = (void*)req_pkt->data;
    req_pkt->type = UDRV_FB_PKT_SET_MODE;
    req_pkt->flags = 0;
    set_mode->mode = mode;

    udrv_send_user_pkt(&dev->udrv_dev,req_pkt);

    // Wait for userspace to actually finish setting the mode
    // (Ensure that it did so successfully)
    // TODO 

    // Destroy the old mode if it existed
    if(dev->current_mode != NULL) {
	udrv_fb_dev_mode_info_put_ref(dev->current_mode);
	dev->current_mode = NULL;
    }
   
    // Set the new mode
    dev->current_mode = new_mode;
    udrv_fb_dev_mode_info_get_ref(dev->current_mode);

    return 0;
}

static int
udrv_fb_set_mode(
	struct fb_dev *fb_dev,
	size_t mode)
{
    int res;
    struct udrv_fb_dev *dev = container_of(fb_dev, struct udrv_fb_dev, fb_dev);
    irq_lock_acquire(&dev->mode_lock);
    res = __udrv_fb_set_mode_lockless(dev, mode);
    irq_lock_release(&dev->mode_lock);
    return res;
}

static int
udrv_fb_load_buffer(
	struct fb_dev *fb_dev,
	void __phys **buffer)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(buffer));

    struct udrv_fb_dev *dev = container_of(fb_dev, struct udrv_fb_dev, fb_dev);
    irq_lock_acquire(&dev->mode_lock);
    if(dev->buffer_size > 0) {
        irq_lock_release(&dev->mode_lock);
	return -EALREADY;
    }
    if(dev->current_mode == NULL) {
        irq_lock_release(&dev->mode_lock);
	return -ENXIO;
    }

    size_t buflen = dev->current_mode->mode_info.buffer_size;

    res = dma_alloc(buflen, VMEM_MIN_PAGE_ORDER, DMA_PHYS_64, &dev->buffer);
    if(res) {
        irq_lock_release(&dev->mode_lock);
	return -ENOMEM;
    }

    dev->buffer_size = buflen;
    *buffer = dma_phys_addr(dev->buffer);

    void *vbuf = dma_virt_addr(dev->buffer);
    DEBUG_ASSERT(KERNEL_ADDR(vbuf));
    //memset(vbuf, 'A', buflen);

    irq_lock_release(&dev->mode_lock);
    return 0;
}

static int
udrv_fb_unload_buffer(
	struct fb_dev *fb_dev,
	void __phys *buffer)
{
    struct udrv_fb_dev *dev = container_of(fb_dev, struct udrv_fb_dev, fb_dev);
    irq_lock_acquire(&dev->mode_lock);
    if(dev->buffer_size <= 0) {
        irq_lock_release(&dev->mode_lock);
	return -EINVAL;
    }
    dma_free(dev->buffer, dev->buffer_size);
    dev->buffer_size = 0;
    irq_lock_release(&dev->mode_lock);
    return 0;
}

static int
udrv_fb_flush_buffer(
	struct fb_dev *fb_dev)
{
    struct udrv_fb_dev *dev = container_of(fb_dev, struct udrv_fb_dev, fb_dev);

    irq_lock_acquire(&dev->mode_lock);

    if(dev->buffer_size <= 0 || dev->current_mode == NULL) {
	// We don't have a current buffer and/or mode...
        irq_lock_release(&dev->mode_lock);
	return -EINVAL;
    }

#define DESIRED_MAX_PACKET_LEN (0x10000)
#define MAX_PACKET_LEN (DESIRED_MAX_PACKET_LEN > FILE_READ_MAX_BUFSIZE ? FILE_READ_MAX_BUFSIZE : DESIRED_MAX_PACKET_LEN)
#define MAX_DATA_LEN (MAX_PACKET_LEN - (sizeof(struct udrv_pkt) + sizeof(struct udrv_fb_pkt_write_to_buffer)))

    ssize_t amt_to_write = dev->buffer_size;
    ssize_t offset = 0;

    void *vbuf = dma_virt_addr(dev->buffer);

    while(amt_to_write > 0)
    {
	size_t datalen = (amt_to_write > MAX_DATA_LEN) ? MAX_DATA_LEN : amt_to_write;
        struct udrv_pkt *req_pkt
            = udrv_create_user_pkt(sizeof(*req_pkt)
            	             + sizeof(struct udrv_fb_pkt_write_to_buffer)
			     + datalen);
	if(req_pkt == NULL) {
	    wprintk("failed to allocated udrv packet during udrv fb_dev flush operation!\n");
	    break;
	}
        struct udrv_fb_pkt_write_to_buffer *pkt = (void*)req_pkt->data;
        req_pkt->type = UDRV_FB_PKT_WRITE_TO_BUFFER;
        req_pkt->flags = 0;
        pkt->offset = offset;
	pkt->datalen = datalen;
	memcpy(pkt->data, vbuf + offset, datalen);

        udrv_send_user_pkt(&dev->udrv_dev,req_pkt);

	amt_to_write -= datalen;
	offset += datalen;
    }

    irq_lock_release(&dev->mode_lock);

    if(amt_to_write > 0) {
	return -EFAULT;
    }

    return 0;

#undef DESIRED_MAX_PACKET_LEN
#undef MAX_PACKET_LEN
#undef MAX_DATA_LEN
}

static struct fb_mode_info *
udrv_fb_get_mode_info(
	struct fb_dev *fb_dev,
	size_t mode)
{
    struct udrv_fb_dev *dev = container_of(fb_dev, struct udrv_fb_dev, fb_dev);
    irq_lock_acquire(&dev->mode_lock);
    ilist_node_t *iter;
    ilist_for_each(iter, &dev->mode_info_list) {
	struct udrv_fb_dev_mode_info *info =
	    container_of(iter, struct udrv_fb_dev_mode_info, list_node);
	if(info->index == mode) {
	    udrv_fb_dev_mode_info_get_ref(info);
            irq_lock_release(&dev->mode_lock);
	    return &info->mode_info;
	}
    }
    irq_lock_release(&dev->mode_lock);
    return NULL;
}

static int
udrv_fb_put_mode_info(
	struct fb_dev *fb_dev,
	size_t mode)
{
    struct udrv_fb_dev *dev = container_of(fb_dev, struct udrv_fb_dev, fb_dev);

    irq_lock_acquire(&dev->mode_lock);
    ilist_node_t *iter;
    ilist_for_each(iter, &dev->mode_info_list) {
	struct udrv_fb_dev_mode_info *info =
	    container_of(iter, struct udrv_fb_dev_mode_info, list_node);
	if(info->index == mode) {
	    udrv_fb_dev_mode_info_put_ref(info);
            irq_lock_release(&dev->mode_lock);
	    return 0;
	}
    }
    irq_lock_release(&dev->mode_lock);
    return -ENXIO;
}

static struct fb_driver
udrv_fb_driver = {
    .get_mode = udrv_fb_get_mode,
    .set_mode = udrv_fb_set_mode,
    .load_buffer = udrv_fb_load_buffer,
    .unload_buffer = udrv_fb_unload_buffer,
    .flush_buffer = udrv_fb_flush_buffer,
    .get_mode_info = udrv_fb_get_mode_info,
    .put_mode_info = udrv_fb_put_mode_info,
};

