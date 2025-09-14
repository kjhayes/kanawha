
#include <kanawha/init.h>
#include <kanawha/dev/kbd.h>
#include <kanawha/kmalloc.h>
#include <kanawha/udrv.h>
#include <kanawha/uapi/udrv/kbd.h>

struct udrv_kbd_dev {
    struct udrv_dev udrv_dev;
    struct kbd_dev kbd_dev;
    
    char *name;
};

static struct udrv_dev *
kbd_dev_udrv_create(
	struct udrv_mount *mnt,
	const char *name)
{
    int res;

    struct udrv_kbd_dev *dev = kmalloc(sizeof(*dev), KM_KERNEL);
    if(dev == NULL) {
	return NULL;
    }

    dev->name = kstrdup(name);
    if(dev->name == NULL) {
	kfree(dev);
	return NULL;
    }

    res = register_kbd_dev(&dev->kbd_dev, dev->name);
    if(res) {
	kfree(dev->name);
	kfree(dev);
	return NULL;
    }

    return &dev->udrv_dev;
}

static int
kbd_dev_udrv_destroy(
	struct udrv_mount *mnt,
	struct udrv_dev *udrv_dev)
{
    int res;

    struct udrv_kbd_dev *dev = container_of(udrv_dev, struct udrv_kbd_dev, udrv_dev);

    res = unregister_kbd_dev(&dev->kbd_dev);
    if(res) {
	return res;
    }

    kfree(dev->name);
    kfree(dev);

    return 0;
}

static int
kbd_dev_udrv_on_recv(
	struct udrv_mount *mnt,
	struct udrv_dev *udrv_dev,
	struct udrv_pkt *pkt,
	size_t pktlen)
{
    int res;

    struct udrv_kbd_dev *dev = container_of(udrv_dev, struct udrv_kbd_dev, udrv_dev);
    struct kbd_dev *kbd = &dev->kbd_dev;

    switch(pkt->type) {
	case UDRV_KBD_PKT_PROVIDE_INPUT:
	    if(pktlen - sizeof(struct udrv_pkt) < sizeof(struct kbd_event)) {
		wprintk("Userspace provided %s with a PROVIDE_INPUT packet of length 0x%lx < 0x%lx!\n",
			pktlen,
			sizeof(struct udrv_pkt) + sizeof(struct kbd_event));
		return -EINVAL;
	    }
	    dprintk("udrv %s sending key event: %s\n",
		    kbd_dev_get_name(kbd),
		    kbd_key_to_string(((struct kbd_event*)pkt->data)->key));
	    res = kbd_driver_enqueue_event(kbd, (struct kbd_event*)pkt->data);
	    if(res) {
		return res;
	    }
	    return 0;
	default:
	    wprintk("udrv: kbd_dev Received invalid packet! (type=%ld)\n",
		    (sl_t)pkt->type);
	    return -EINVAL;
    }
}

static struct udrv_mount_ops
kbd_dev_udrv_mount_ops = {
    .create = kbd_dev_udrv_create,
    .destroy = kbd_dev_udrv_destroy,
    .on_recv = kbd_dev_udrv_on_recv,
};

static struct udrv_mount
kbd_dev_udrv_mount = {
    .ops = &kbd_dev_udrv_mount_ops,
};

static int
register_kbd_dev_udrv(void)
{
    int res;
    res = register_udrv_mount(&kbd_dev_udrv_mount, "kbd");
    if(res) {
	return res;
    }
    return 0;
}
declare_init_desc(fs, register_kbd_dev_udrv, "Registering kbd_dev Userspace Driver Framework");

