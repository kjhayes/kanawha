
#include <kanawha/init.h>
#include <kanawha/dev/rand.h>
#include <kanawha/kmalloc.h>
#include <kanawha/udrv.h>
#include <kanawha/uapi/udrv/rand.h>

static struct rand_driver udrv_rand_driver;

#define UDRV_RAND_BUFLEN 256

struct udrv_rand_dev {
    struct udrv_dev udrv_dev;
    struct rand_dev rand_dev;

    char *name;

    irq_lock_t buflock;
    size_t bufindex;
    size_t datalen;
    uint8_t buffer[UDRV_RAND_BUFLEN];
};

static struct udrv_dev *
rand_dev_udrv_create(
	struct udrv_mount *mnt,
	const char *name)
{
    int res;

    struct udrv_rand_dev *dev = kmalloc(sizeof(*dev), KM_KERNEL);
    if(dev == NULL) {
	return NULL;
    }

    dev->name = kstrdup(name);
    if(dev->name == NULL) {
	kfree(dev);
	return NULL;
    }

    dev->bufindex = 0;
    dev->datalen = 0;
    memset(dev->buffer, 0, UDRV_RAND_BUFLEN);
    irq_lock_init(&dev->buflock);

    dev->rand_dev.driver = &udrv_rand_driver;

    res = register_rand_dev(&dev->rand_dev, dev->name);
    if(res) {
	kfree(dev->name);
	kfree(dev);
	return NULL;
    }

    return &dev->udrv_dev;
}

static int
rand_dev_udrv_destroy(
	struct udrv_mount *mnt,
	struct udrv_dev *udrv_dev)
{
    int res;

    struct udrv_rand_dev *dev = container_of(udrv_dev, struct udrv_rand_dev, udrv_dev);

    res = unregister_rand_dev(&dev->rand_dev);
    if(res) {
	return res;
    }

    kfree(dev->name);
    kfree(dev);

    return 0;
}

static int
rand_dev_udrv_on_recv(
	struct udrv_mount *mnt,
	struct udrv_dev *udrv_dev,
	struct udrv_pkt *pkt,
	size_t pktlen)
{
    struct udrv_rand_dev *dev = container_of(udrv_dev, struct udrv_rand_dev, udrv_dev);

    switch(pkt->type) {
	case UDRV_RAND_PKT_PROVIDE_ENTROPY:
	    irq_lock_acquire(&dev->buflock);
	    if(dev->datalen != 0) {
	        irq_lock_release(&dev->buflock);
		    return -EWOULDBLOCK;
	    } else {
		    ssize_t datalen = MIN(pktlen - sizeof(*pkt), UDRV_RAND_BUFLEN);
		    if(datalen <= 0) {
	            irq_lock_release(&dev->buflock);
		        return -EINVAL;
		    }

		    dev->datalen = datalen;
		    dev->bufindex = 0;
		    memcpy(dev->buffer, pkt->data, datalen);

	        irq_lock_release(&dev->buflock);

		    rand_dev_wake_readers(&dev->rand_dev);

		    return 0;
	    }
	    break;
	default:
	    printk("udrv: rand_dev Received invalid packet! (type=%ld)\n",
		    (sl_t)pkt->type);
	    return -EINVAL;
    }
}

static struct udrv_mount_ops
rand_dev_udrv_mount_ops = {
    .create = rand_dev_udrv_create,
    .destroy = rand_dev_udrv_destroy,
    .on_recv = rand_dev_udrv_on_recv,
};

static struct udrv_mount
rand_dev_udrv_mount = {
    .ops = &rand_dev_udrv_mount_ops,
};

static int
register_rand_dev_udrv(void)
{
    int res;
    res = register_udrv_mount(&rand_dev_udrv_mount, "rand");
    if(res) {
	return res;
    }
    return 0;
}
declare_init_desc(fs, register_rand_dev_udrv, "Registering rand_dev Userspace Driver Framework");

static ssize_t
udrv_rand_dev_read(
	struct rand_dev *rand_dev,
	void *buffer,
	size_t buflen)
{
    ssize_t amt_read;

    struct udrv_rand_dev *dev = container_of(rand_dev, struct udrv_rand_dev, rand_dev);

    irq_lock_acquire(&dev->buflock);

    if(dev->datalen == 0) {
        irq_lock_release(&dev->buflock);
	    return -EWOULDBLOCK;
    }

    // This is slow... but I'll keep it simple
    amt_read = 0;
    while(dev->bufindex < dev->datalen && buflen > 0)
    {
	    *(uint8_t*)buffer = dev->buffer[dev->bufindex];

	    dev->bufindex++;
	    buffer++;
	    buflen--;
	    amt_read++;
    }

    if(amt_read == 0 || dev->bufindex == dev->datalen) {
	    dev->datalen = 0;
	    dev->bufindex = 0;
	    udrv_wake_driver(&dev->udrv_dev);
	    if(amt_read == 0) {
            irq_lock_release(&dev->buflock);
	        return -EWOULDBLOCK;
	    }
    }

    irq_lock_release(&dev->buflock);

    return amt_read;
}

static struct rand_driver
udrv_rand_driver = {
    .read = udrv_rand_dev_read,
};

