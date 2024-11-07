
#include <kanawha/init.h>
#include <kanawha/dma.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/stddef.h>
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

    size_t recv_bufsize;
    dma_addr_t recv_buffer;

    size_t xmit_bufsize;
    dma_addr_t xmit_buffer;

    ilist_node_t list_node;
};

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
        printk("virtio_console: Accepted VIRTIO_CONSOLE_F_SIZE Feature\n");
    }
//    if(virtio_device_check_feature(device, VIRTIO_CONSOLE_F_MULTIPORT))
//    {
//        virtio_device_accept_feature(device, VIRTIO_CONSOLE_F_MULTIPORT);
//        printk("virtio_console: Accepted VIRTIO_CONSOLE_F_MULTIPORT Feature\n");
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

    printk("virtio_console_init_device\n");

    if(device->num_queues < 4) {
        eprintk("virtio_console: Device must have at least 4 virt queues! (num_queues=0x%lx)\n",
                device->num_queues);
        return -EINVAL;
    }

    struct virtio_console_device *cdev = kmalloc(sizeof(struct virtio_console_device));
    if(cdev == NULL) {
        return -ENOMEM;
    }
    memset(cdev, 0, sizeof(struct virtio_console_device));

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

        struct virtio_console_port *port = kmalloc(sizeof(struct virtio_console_port));
        if(port == NULL) {
            res = -ENOMEM;
            ports_failed = 1;
            break;
        }
        memset(port, 0, sizeof(struct virtio_console_port));

        port->device = cdev;
        port->xmit_queue = xmit_queue;
        port->recv_queue = recv_queue;

        port->xmit_bufsize = VIRTIO_CONSOLE_BUFSIZE;
        port->recv_bufsize = VIRTIO_CONSOLE_BUFSIZE;

        res = dma_alloc(port->recv_bufsize, 0, DMA_PHYS_64, &port->recv_buffer);
        if(res) {
            kfree(port);
            ports_failed = 1;
            break;
        }
        memset(dma_virt_addr(port->recv_buffer), 0, port->recv_bufsize);

        res = dma_alloc(port->xmit_bufsize, 0, DMA_PHYS_64, &port->xmit_buffer);
        if(res) {
            dma_free(port->recv_buffer, port->recv_bufsize);
            kfree(port);
            ports_failed = 1;
            break;
        }
        memset(dma_virt_addr(port->xmit_buffer), 0, port->xmit_bufsize);

        res = virtio_queue_enable(port->recv_queue);
        if(res) {
            dma_free(port->recv_buffer, port->recv_bufsize);
            dma_free(port->xmit_buffer, port->xmit_bufsize);
            kfree(port);
            ports_failed = 1;
            break;
        }

        res = virtio_queue_enable(port->xmit_queue);
        if(res) {
            virtio_queue_disable(port->recv_queue);
            dma_free(port->recv_buffer, port->recv_bufsize);
            dma_free(port->xmit_buffer, port->xmit_bufsize);
            kfree(port);
            ports_failed = 1;
            break;
        }
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

            dma_free(port->recv_buffer, port->recv_bufsize);
            dma_free(port->xmit_buffer, port->xmit_bufsize);
            kfree(port);
        }
        virtio_queue_disable(cdev->ctrl_xmit_queue);
        virtio_queue_disable(cdev->ctrl_recv_queue);
        kfree(cdev);
        return res;
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

