
#include <kanawha/init.h>
#include <kanawha/dev/input.h>
#include <kanawha/kmalloc.h>
#include <kanawha/udrv.h>
#include <kanawha/uapi/udrv/input.h>

struct udrv_input_dev {
    struct udrv_dev udrv_dev;
    struct input_dev input_dev;
    
    char *name;
};

static struct udrv_dev *
input_dev_udrv_create(
	struct udrv_mount *mnt,
	const char *name)
{
    int res;

    struct udrv_input_dev *dev = kmalloc(sizeof(*dev), KM_KERNEL);
    if(dev == NULL) {
	return NULL;
    }

    dev->name = kstrdup(name);
    if(dev->name == NULL) {
	kfree(dev);
	return NULL;
    }

    res = register_input_dev(&dev->input_dev, dev->name);
    if(res) {
	kfree(dev->name);
	kfree(dev);
	return NULL;
    }

    return &dev->udrv_dev;
}

static int
input_dev_udrv_destroy(
	struct udrv_mount *mnt,
	struct udrv_dev *udrv_dev)
{
    int res;

    struct udrv_input_dev *dev = container_of(udrv_dev, struct udrv_input_dev, udrv_dev);

    res = unregister_input_dev(&dev->input_dev);
    if(res) {
	return res;
    }

    kfree(dev->name);
    kfree(dev);

    return 0;
}

static int
input_dev_udrv_on_recv(
	struct udrv_mount *mnt,
	struct udrv_dev *udrv_dev,
	struct udrv_pkt *pkt,
	size_t pktlen)
{
    int res;

    struct udrv_input_dev *dev = container_of(udrv_dev, struct udrv_input_dev, udrv_dev);
    struct input_dev *input = &dev->input_dev;

    switch(pkt->type) {
	  case UDRV_INPUT_PKT_PROVIDE_INPUT:
	    if(pktlen - sizeof(struct udrv_pkt) < sizeof(struct input_event)) {
		wprintk("Userspace provided %s with a PROVIDE_INPUT packet of length 0x%lx < 0x%lx!\n",
			pktlen,
			sizeof(struct udrv_pkt) + sizeof(struct input_event));
		return -EINVAL;
	    }
	    dprintk("udrv %s sending key event: %s\n",
		    input_dev_get_name(input),
		    input_key_to_string(((struct input_event*)pkt->data)->key));
	    res = input_driver_enqueue_event(input, (struct input_event*)pkt->data);
	    if(res) {
		return res;
	    }
	    return 0;
	  default:
	    wprintk("udrv: input_dev Received invalid packet! (type=%ld)\n",
		    (sl_t)pkt->type);
	    return -EINVAL;
    }
}

static struct udrv_mount_ops
input_dev_udrv_mount_ops = {
    .create = input_dev_udrv_create,
    .destroy = input_dev_udrv_destroy,
    .on_recv = input_dev_udrv_on_recv,
};

static struct udrv_mount
input_dev_udrv_mount = {
    .ops = &input_dev_udrv_mount_ops,
};

static int
register_input_dev_udrv(void)
{
    int res;
    res = register_udrv_mount(&input_dev_udrv_mount, "input");
    if(res) {
	return res;
    }
    return 0;
}
declare_init_desc(fs, register_input_dev_udrv, "Registering input_dev Userspace Driver Framework");

