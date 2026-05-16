
#include <drivers/virtio/virtio.h>
#include <drivers/virtio/driver.h>
#include <drivers/virtio/monitor.h>
#include <drivers/input/linux.h>
#include <kanawha/kmalloc.h>
#include <kanawha/endian.h>
#include <kanawha/attribute.h>
#include <kanawha/ptree.h>
#include <kanawha/dev/input.h>

static DECLARE_PTREE(virtio_input_tree);

struct virtio_input {
    struct input_dev input_dev;
    struct virtio_device *virtio_dev;
    char *name;

    struct virtio_monitor *evt_monitor;

    struct ptree_node ptree_node;
};

struct virtio_input_event {
    le16_t type;
    le16_t code;
    le32_t value;
} __packed;

static int
virtio_input_event_monitor_callback(
        void *buffer,
        size_t buflen,
        void *state)
{
    int res;
    struct virtio_input *input = state;
    if(buflen < sizeof(struct virtio_input_event)) {
        return -EINVAL;
    }
    struct virtio_input_event *evt = buffer;

    struct input_event input_evt;
    res = input_event_from_linux(
            letoh32(evt->type),
            letoh32(evt->code),
            letoh32(evt->value),
            &input_evt);
    if(res) {
        return res;
    }
    input_driver_enqueue_event(
            &input->input_dev,
            &input_evt);
    return 0;
}

static int
virtio_input_probe(struct virtio_driver *driver, struct virtio_device *device)
{
    dprintk("virtio_input_probe\n");
    return 0;
}

static int
virtio_input_negotiate(struct virtio_driver *driver, struct virtio_device *device)
{
    dprintk("virtio_input_negotiate\n");
    return 0;
}

static int
virtio_input_init_device(struct virtio_driver *driver,
                       struct virtio_device *device)
{
    int res;

    dprintk("virtio_input_init_device\n");

    if(device->num_queues < 1)
    {
        eprintk("virtio_input: found device with invalid number of queues (expected at least 1, got %lu)\n",
                (ul_t)device->num_queues);
        return -EINVAL;
    }

    struct virtio_input *input = kzmalloc(sizeof(struct virtio_input), KM_KERNEL);
    if(input == NULL)
    {
        eprintk("virtio_input: failed to allocate device structure!\n");
        return -ENOMEM;
    }
    memset(input, 0, sizeof(struct virtio_input));

    input->virtio_dev = device;
    device->driver_priv = input;

    struct virtio_queue *evt_queue = input->virtio_dev->queues[0];
    DEBUG_ASSERT(KERNEL_ADDR(evt_queue));

    printk("virtio_input: evt_queue=%p\n", evt_queue);

    input->evt_monitor = virtio_monitor_create(
            evt_queue,
            8,
            sizeof(struct virtio_input_event),
            virtio_input_event_monitor_callback,
            input);
    if(input->evt_monitor == NULL) {
        eprintk("virtio_input: failed to create virtio event monitor!\n");
        kfree(input);
        return -ENOMEM;
    }

    res = ptree_insert_any(&virtio_input_tree, &input->ptree_node);
    if(res) {
        eprintk("virtio_input: failed to get device index!\n");
        kfree(input);
        return res;
    }

#define NAMEBUFLEN 64
    char namebuf[NAMEBUFLEN];
    snprintk(namebuf, NAMEBUFLEN, "virtio-input-%ld", (sl_t)input->ptree_node.key);
    namebuf[NAMEBUFLEN - 1] = '\0';
#undef NAMEBUFLEN

    input->name = kstrdup(namebuf);
    if(input->name == NULL)
    {
        eprintk("virtio_input: failed to allocate device name buffer!\n");
        kfree(input);
        return -ENOMEM;
    }

    res = register_input_dev(&input->input_dev, input->name);
    if(res)
    {
        eprintk("virtio_input: failed to register input_dev (err=%s)!\n",
                errnostr(res));
        kfree(input->name);
        kfree(input);
        return res;
    }

    res = virtio_monitor_start(input->evt_monitor);
    if(res) {
        wprintk("virtio-input: failed to start event monitor!\n");
    }

    return 0;
}

static int
virtio_input_deinit_device(struct virtio_driver *driver,
                         struct virtio_device *device)
{
    int res;

    struct virtio_input *input;
    input = device->driver_priv;

    res = virtio_monitor_stop(input->evt_monitor);
    if(res) {
        return res;
    }
    res = virtio_monitor_destroy(input->evt_monitor);
    if(res) {
        return res;
    }

    struct ptree_node *rem = ptree_remove(&virtio_input_tree, input->ptree_node.key);
    DEBUG_ASSERT(rem == &input->ptree_node);

    res = unregister_input_dev(&input->input_dev);
    if(res) {
        return res;
    }

    kfree(input);

    return 0;
}

static struct virtio_driver_ops virtio_input_virtio_driver_ops = {
    .probe = virtio_input_probe,
    .negotiate = virtio_input_negotiate,
    .init_device = virtio_input_init_device,
    .deinit_device = virtio_input_deinit_device,
};

static uint16_t virtio_input_virtio_ids[] = {
    18,
};

static struct virtio_driver virtio_input_virtio_driver = {
    .ops = &virtio_input_virtio_driver_ops,
    .num_ids = sizeof(virtio_input_virtio_ids) / sizeof(uint16_t),
    .ids = virtio_input_virtio_ids,
};

static int
register_virtio_input_driver(void)
{
    return register_virtio_driver(&virtio_input_virtio_driver);
}
declare_init_desc(device,
                  register_virtio_input_driver,
                  "Registered Virtio Input Driver");
