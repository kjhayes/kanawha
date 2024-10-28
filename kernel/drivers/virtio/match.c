
#include <drivers/virtio/driver.h>
#include <drivers/virtio/virtio.h>
#include <kanawha/list.h>
#include <kanawha/stddef.h>

static DECLARE_SPINLOCK(virtio_match_lock);
static DECLARE_ILIST(virtio_unmatched_device_list);
static DECLARE_ILIST(virtio_matched_device_list);
static DECLARE_ILIST(virtio_driver_list);

static int
virtio_try_match(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    int res;

    printk("virtio_try_match\n");

    int matched_id = 0;
    for(size_t i = 0; i < driver->num_ids; i++) {
        printk("Checking: driver 0x%x, device 0x%x\n",
                driver->ids[i], device->virtio_id);
        if(driver->ids[i] == device->virtio_id)
        {
            matched_id = 1;
            break;
        }
    }

    if(!matched_id) {
        return -EINVAL;
    }

    res = virtio_driver_probe(driver, device);
    if(res) {
        return res;
    }

    res = virtio_driver_init_device(driver, device);
    if(res) {
        return res;
    }

    device->driver = driver;
    ilist_push_tail(&driver->device_list, &device->driver_node);

    return 0;
}

int
register_virtio_device(
        struct virtio_device *device)
{
    int res;

    uint64_t status = virtio_device_read_status(device);
    if(status) {
        eprintk("register_virtio_device: Device Status is non-zero! (status=0x%lx)\n",
                status);
        return -EINVAL; // Nothing should have configured the device at this point
    }


    // Acknowledge the device as a virtio device
    res = virtio_device_set_status(device, VIRTIO_STATUS_ACKNOWLEDGE);
    if(res) {
        return res;
    }

    // Make sure the acknowledge bit was set correctly
    status = virtio_device_read_status(device);
    if(!(status & VIRTIO_STATUS_ACKNOWLEDGE)) {
        eprintk("register_virtio_device: Failed to acknowledge virtio device! (status=0x%lx)\n",
                status);
        return -EINVAL;
    }


    spin_lock(&virtio_match_lock);

    int matched = 0;
    ilist_node_t *node;
    ilist_for_each(node, &virtio_driver_list) {
        struct virtio_driver *driver =
            container_of(node, struct virtio_driver, global_node);
        res = virtio_try_match(driver, device);
        if(res) {
            continue;
        }
        matched = 1;
        break;
    }

    if(matched) {
        ilist_push_tail(&virtio_matched_device_list, &device->global_node);
    } else {
        ilist_push_tail(&virtio_unmatched_device_list, &device->global_node);
    }

    spin_unlock(&virtio_match_lock);
    return 0;
}

int
register_virtio_driver(
        struct virtio_driver *driver)
{
    int res;

    ilist_init(&driver->device_list);

    spin_lock(&virtio_match_lock);

    ilist_push_tail(&virtio_driver_list, &driver->global_node);

    int matched = 0;
    ilist_node_t *node;
    ilist_for_each(node, &virtio_unmatched_device_list) {
        struct virtio_device *device =
            container_of(node, struct virtio_device, global_node);
        res = virtio_try_match(driver, device);
        if(res) {
            continue;
        }
    }

    ilist_for_each(node, &driver->device_list) {
        struct virtio_device *device =
            container_of(node, struct virtio_device, global_node);
        ilist_remove(&virtio_unmatched_device_list, &device->global_node);
        ilist_push_tail(&virtio_matched_device_list, &device->global_node);
    }

    spin_unlock(&virtio_match_lock);

    return 0;
}

