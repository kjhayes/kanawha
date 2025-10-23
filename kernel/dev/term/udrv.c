
#include <kanawha/init.h>
#include <kanawha/dev/term.h>
#include <kanawha/kmalloc.h>
#include <kanawha/udrv.h>
#include <kanawha/uapi/udrv/term.h>

static struct term_driver udrv_term_driver;

struct udrv_term_dev {
    struct udrv_dev udrv_dev;
    struct term_dev term_dev;

    char *name;
};

static struct udrv_dev *
term_dev_udrv_create(
	struct udrv_mount *mnt,
	const char *name)
{
    int res;

    struct udrv_term_dev *dev = kmalloc(sizeof(*dev), KM_KERNEL);
    if(dev == NULL) {
	return NULL;
    }

    dev->name = kstrdup(name);
    if(dev->name == NULL) {
	kfree(dev);
	return NULL;
    }

    dev->term_dev.driver = &udrv_term_driver;
    res = register_term_dev(&dev->term_dev, dev->name);
    if(res) {
	kfree(dev->name);
	kfree(dev);
	return NULL;
    }

    return &dev->udrv_dev;
}

static int
term_dev_udrv_destroy(
	struct udrv_mount *mnt,
	struct udrv_dev *udrv_dev)
{
    int res;

    struct udrv_term_dev *dev = container_of(udrv_dev, struct udrv_term_dev, udrv_dev);

    res = unregister_term_dev(&dev->term_dev);
    if(res) {
	return res;
    }

    kfree(dev->name);
    kfree(dev);

    return 0;
}

static int
term_dev_udrv_on_recv(
	struct udrv_mount *mnt,
	struct udrv_dev *udrv_dev,
	struct udrv_pkt *pkt,
	size_t pktlen)
{
    struct udrv_term_dev *dev = container_of(udrv_dev, struct udrv_term_dev, udrv_dev);

    switch(pkt->type) {
	case UDRV_TERM_PKT_PROVIDE_INPUT:
	    {
		size_t datalen = pktlen - sizeof(*pkt);
		for(size_t i = 0; i < datalen; i++) {
                    //printk("udrv_term_provide_input\n");
		    term_driver_provide_input(&dev->term_dev, pkt->data[i]);
		}
		break;
	    }
	default:
	    printk("udrv: term_dev Received invalid packet from userspace! (type=%ld)\n",
		    (sl_t)pkt->type);
	    return -EINVAL;
    }

    return 0;
}

static struct udrv_mount_ops
term_dev_udrv_mount_ops = {
    .create = term_dev_udrv_create,
    .destroy = term_dev_udrv_destroy,
    .on_recv = term_dev_udrv_on_recv,
};

static struct udrv_mount
term_dev_udrv_mount = {
    .ops = &term_dev_udrv_mount_ops,
};

static int
register_term_dev_udrv(void)
{
    int res;
    res = register_udrv_mount(&term_dev_udrv_mount, "term");
    if(res) {
	return res;
    }
    return 0;
}
declare_init_desc(fs, register_term_dev_udrv, "Registering term_dev Userspace Driver Framework");

static int
udrv_term_dev_putc(
	struct term_dev *term_dev,
	char c)
{
    struct udrv_term_dev *dev = container_of(term_dev, struct udrv_term_dev, term_dev);

    //printk("udrv_term_putc\n");

    // TODO Queue these up and actually do the sending in "flush"
    //      instead of sending them one by one
    struct udrv_pkt *pkt = udrv_create_user_pkt(sizeof(*pkt)+1);
    pkt->type = UDRV_TERM_PKT_PUTCHARS;
    pkt->flags = 0;
    pkt->data[0] = c;
    udrv_send_user_pkt(&dev->udrv_dev, pkt);

    return 0;
}

static int
udrv_term_dev_flush(
	struct term_dev *term_dev)
{
    struct udrv_term_dev *dev = container_of(term_dev, struct udrv_term_dev, term_dev);
    return 0;
}

static int
udrv_term_dev_set_baudrate(
	struct term_dev *term_dev,
	baud_t baud)
{
    struct udrv_term_dev *dev = container_of(term_dev, struct udrv_term_dev, term_dev);
    if(baud != 0) {
	return -EINVAL;
    }
    return 0;
}

static int
udrv_term_dev_get_baudrate(
	struct term_dev *term_dev,
	baud_t *baud)
{
    struct udrv_term_dev *dev = container_of(term_dev, struct udrv_term_dev, term_dev);
    *baud = 0;
    return 0;
}

static struct term_driver
udrv_term_driver = {
    .putc = udrv_term_dev_putc,
    .flush = udrv_term_dev_flush,
    .set_baudrate = udrv_term_dev_set_baudrate,
    .get_baudrate = udrv_term_dev_get_baudrate,
};

