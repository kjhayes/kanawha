
#include <kanawha/init.h>
#include <kanawha/dma.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/stddef.h>
#include <kanawha/dev/term.h>
#include <kanawha/spinlock.h>
#include <drivers/virtio/driver.h>
#include <drivers/virtio/virtio.h>
#include <drivers/virtio/queue.h>
#include <drivers/virtio/request.h>

#define VIRTIO_CONSOLE_F_SIZE (0)
#define VIRTIO_CONSOLE_F_MULTIPORT (1)
#define VIRTIO_CONSOLE_F_EMERG_WRITE (2)

#define VIRTIO_CONSOLE_BUFSIZE 0x1000

struct virtio_console_device
{
    struct virtio_device *device;

    struct virtio_queue *ctrl_recv_queue;
    struct virtio_queue *ctrl_xmit_queue;

    size_t num_ports;
    ilist_t port_list;
};

struct virtio_console_port
{
    struct virtio_console_device *device;

    struct virtio_queue *recv_queue;
    struct virtio_queue *xmit_queue;

    ilist_node_t list_node;

    spinlock_t lock;
    struct term_dev term_dev;

    char *name;
};

static struct term_driver virtio_console_port_term_driver;

static int
virtio_console_probe(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    dprintk("virtio_console_probe\n");
    return 0;
}

static int
virtio_console_negotiate(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    if(virtio_device_check_feature(device, VIRTIO_CONSOLE_F_SIZE))
    {
        virtio_device_accept_feature(device, VIRTIO_CONSOLE_F_SIZE);
        dprintk("virtio_console: Accepted VIRTIO_CONSOLE_F_SIZE Feature\n");
    }
//    if(virtio_device_check_feature(device, VIRTIO_CONSOLE_F_MULTIPORT))
//    {
//        virtio_device_accept_feature(device, VIRTIO_CONSOLE_F_MULTIPORT);
//        dprintk("virtio_console: Accepted VIRTIO_CONSOLE_F_MULTIPORT Feature\n");
//    } else {
//        return -EINVAL;
//    }
    return 0;
}

static int
virtio_console_init_device(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    int res;

    dprintk("virtio_console_init_device\n");

    if(device->num_queues < 4) {
        eprintk("virtio_console: Device must have at least 4 virt queues! (num_queues=0x%lx)\n",
                device->num_queues);
        return -EINVAL;
    }

    struct virtio_console_device *cdev =
	kzmalloc(sizeof(struct virtio_console_device), KM_KERNEL);
    if(cdev == NULL) {
        return -ENOMEM;
    }

    DEBUG_ASSERT(KERNEL_ADDR(device->queues));

    cdev->ctrl_recv_queue = device->queues[2];
    cdev->ctrl_xmit_queue = device->queues[3];

    DEBUG_ASSERT(KERNEL_ADDR(cdev->ctrl_recv_queue));
    DEBUG_ASSERT(KERNEL_ADDR(cdev->ctrl_xmit_queue));

    res = virtio_queue_enable(cdev->ctrl_recv_queue);
    if(res) {
        kfree(cdev);
        return res;
    }

    res = virtio_queue_enable(cdev->ctrl_xmit_queue);
    if(res) {
        virtio_queue_disable(cdev->ctrl_recv_queue);
        kfree(cdev);
        return res;
    }

    ilist_init(&cdev->port_list);
    cdev->num_ports = 1; // TODO MULTIPORT

    int ports_failed = 0;
    for(size_t port_i = 0; port_i < cdev->num_ports; port_i++) {

        struct virtio_queue *recv_queue;
        struct virtio_queue *xmit_queue;

        if(port_i == 0) {
            recv_queue = device->queues[0];
            xmit_queue = device->queues[1];
        } else {
            recv_queue = device->queues[2 * (port_i+1)];
            xmit_queue = device->queues[(2 * (port_i+1)) + 1];
        }

        DEBUG_ASSERT(KERNEL_ADDR(recv_queue));
        DEBUG_ASSERT(KERNEL_ADDR(xmit_queue));

        struct virtio_console_port *port =
	    kzmalloc(sizeof(struct virtio_console_port), KM_KERNEL);
        if(port == NULL) {
            res = -ENOMEM;
            ports_failed = 1;
            break;
        }

        port->device = cdev;
        port->xmit_queue = xmit_queue;
        port->recv_queue = recv_queue;
        spinlock_init(&port->lock);

        res = virtio_queue_enable(port->recv_queue);
        if(res) {
            kfree(port);
            ports_failed = 1;
            break;
        }

        res = virtio_queue_enable(port->xmit_queue);
        if(res) {
            kfree(port);
            ports_failed = 1;
            break;
        }

        dprintk("enabled queues\n");

        char namebuf[128];
        snprintk(namebuf, 128, "virtio-console-%ld", 
                (sl_t)port_i);
        namebuf[127] = '\0';

        port->name = kstrdup(namebuf);
        if(port->name == NULL) {
            virtio_queue_disable(port->recv_queue);
            kfree(port);
            ports_failed = 1;
            break;
        }

        ilist_push_tail(&cdev->port_list, &port->list_node);
    }

    if(ports_failed) {
        ilist_node_t *node;
        while(1) {
            node = ilist_pop_tail(&cdev->port_list);
            if(node == NULL) {
                break;
            }
            struct virtio_console_port *port =
                container_of(node, struct virtio_console_port, list_node);

            virtio_queue_disable(port->xmit_queue);
            virtio_queue_disable(port->recv_queue);

            kfree(port->name);
            kfree(port);
        }
        virtio_queue_disable(cdev->ctrl_xmit_queue);
        virtio_queue_disable(cdev->ctrl_recv_queue);
        kfree(cdev);
        return res;
    }

    ilist_node_t *node;
    ilist_for_each(node, &cdev->port_list) {
        struct virtio_console_port *port =
            container_of(node, struct virtio_console_port, list_node);
        port->term_dev.driver = &virtio_console_port_term_driver;
        res = register_term_dev(
                &port->term_dev,
                port->name
                );
        if(res) {
            eprintk("Failed to register virtio console port term_dev! (err=%s)\n",
                    errnostr(res));
        }
    }

    return 0;
}

static int
virtio_console_deinit_device(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    return -EUNIMPL;
}

static struct virtio_driver_ops
virtio_console_driver_ops = {
    .probe = virtio_console_probe,
    .negotiate = virtio_console_negotiate,
    .init_device = virtio_console_init_device,
    .deinit_device = virtio_console_deinit_device,
};

static uint16_t
virtio_console_virtio_ids[] = {
    3,
};

static struct virtio_driver
virtio_console_driver = {
    .ops = &virtio_console_driver_ops,
    .num_ids = sizeof(virtio_console_virtio_ids) / sizeof(uint16_t),
    .ids = virtio_console_virtio_ids,
};

static int
register_virtio_console_driver(void)
{
    return register_virtio_driver(&virtio_console_driver);
}
declare_init_desc(device, register_virtio_console_driver, "Registering Virtio Console Driver");

static ssize_t
virtio_console_term_dev_read(
        struct term_dev *dev,
        void *buffer,
        size_t amount)
{
    int res;

    struct virtio_console_port *port =
        container_of(dev, struct virtio_console_port, term_dev);

    spin_lock(&port->lock);

    dma_addr_t dma_buffer;
    res = dma_alloc(
            amount,
            0,
            DMA_PHYS_64,
            &dma_buffer);
    if(res) {
        spin_unlock(&port->lock);
        return res;
    }

    struct virtio_request *req = virtio_request_create(port->recv_queue);
    if(req == NULL) {
        spin_unlock(&port->lock);
        dma_free(dma_buffer, amount);
        return -ENOMEM;
    }

    res = virtio_request_append_output(
            req,
            dma_phys_addr(dma_buffer),
            amount);
    if(res) {
        virtio_request_destroy(req);
        spin_unlock(&port->lock);
        dma_free(dma_buffer, amount);
        return res;
    }

    res = virtio_request_launch(req);
    if(res) {
        virtio_request_destroy(req);
        spin_unlock(&port->lock);
        dma_free(dma_buffer, amount);
        return res;
    }

    res = virtio_request_await(req);
    if(res) {
        virtio_request_destroy(req);
        spin_unlock(&port->lock);
        dma_free(dma_buffer, amount);
        return res;
    }

    memcpy(buffer, dma_virt_addr(dma_buffer), req->len_written);
    amount = req->len_written;

    virtio_request_destroy(req);
    spin_unlock(&port->lock);

    dma_free(dma_buffer, amount);

    return amount;
}

static ssize_t
virtio_console_term_dev_write(
        struct term_dev *dev,
        void *buffer,
        size_t amount)
{
    int res;

    struct virtio_console_port *port =
        container_of(dev, struct virtio_console_port, term_dev);

    spin_lock(&port->lock);

    dma_addr_t dma_buffer;
    res = dma_alloc(
            amount,
            0,
            DMA_PHYS_64,
            &dma_buffer);
    if(res) {
        spin_unlock(&port->lock);
        return res;
    }

    memcpy(dma_virt_addr(dma_buffer), buffer, amount);

    struct virtio_request *req = virtio_request_create(port->xmit_queue);
    if(req == NULL) {
        spin_unlock(&port->lock);
        dma_free(dma_buffer, amount);
        return -ENOMEM;
    }

    res = virtio_request_append_input(
            req,
            dma_phys_addr(dma_buffer),
            amount);
    if(res) {
        virtio_request_destroy(req);
        spin_unlock(&port->lock);
        dma_free(dma_buffer, amount);
        return res;
    }

    res = virtio_request_launch(req);
    if(res) {
        virtio_request_destroy(req);
        spin_unlock(&port->lock);
        dma_free(dma_buffer, amount);
        return res;
    }

    res = virtio_request_await(req);
    if(res) {
        virtio_request_destroy(req);
        spin_unlock(&port->lock);
        dma_free(dma_buffer, amount);
        return res;
    }

    virtio_request_destroy(req);
    spin_unlock(&port->lock);
    dma_free(dma_buffer, amount);

    return amount;
}

static int
virtio_console_term_dev_flush(
        struct term_dev *dev)
{ 
    int res;

    struct virtio_console_port *port =
        container_of(dev, struct virtio_console_port, term_dev);

    // Nothing to do, we aren't buffering

    return 0;
}

static struct term_driver
virtio_console_port_term_driver = {
    .read = virtio_console_term_dev_read,
    .write = virtio_console_term_dev_write,
    .flush = virtio_console_term_dev_flush,
};

