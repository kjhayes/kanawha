
#include <drivers/usb/usb.h>
#include <drivers/usb/device.h>
#include <kanawha/list.h>
#include <kanawha/lock.h>

static DECLARE_ILIST(drivers_list);
static DECLARE_ILIST(unmatched_devices_list);
DEFINE_LOCAL_THREAD_LOCK(match_lock);

static int
try_match_pair(
        struct usb_device_driver *driver,
        struct usb_device *device)
{
    int res;

    res = usb_device_driver_probe_device(driver, device);
    if(res) {
        return res;
    }

    size_t chosen_config = 0;
    res = usb_device_driver_configure_device(
            driver,
            device,
            &chosen_config);
    if(res) {
        return res;
    }

    // Actually configure the device TODO

    res = usb_device_driver_init_device(driver, device);
    if(res) {
        return res;
    }

    ilist_push_tail(&driver->matched_devices, &device->match_node);
    device->driver = driver;

    return 0;
}

int
register_usb_device(struct usb_device *device)
{
    int res;
    int matched = 0;

    device->driver = NULL;

    match_lock_acquire();
    ilist_node_t *driver_iter;
    ilist_for_each(driver_iter, &drivers_list) {
        struct usb_device_driver *driver =
            container_of(driver_iter, struct usb_device_driver, match_node);
        res = try_match_pair(driver, device);
        if(res == 0) {
            matched = 1;
            break;
        }
    }

    if(!matched) {
        ilist_push_tail(&unmatched_devices_list, &device->match_node);
    }
    match_lock_release();
    return 0;
}
int
unregister_usb_device(struct usb_device *device)
{
    match_lock_acquire();
    //ilist_remove(&unmatched_devices_list, &device->match_node);
    match_lock_release();
    return -EUNIMPL;
}

int
register_usb_device_driver(struct usb_device_driver *driver)
{
    int res;

    ilist_init(&driver->matched_devices);

    match_lock_acquire();
    ilist_push_tail(&drivers_list, &driver->match_node);
    size_t len = ilist_count(&unmatched_devices_list);
    for(size_t i = 0; i < len; i++) {
        ilist_node_t *node = ilist_pop_head(&unmatched_devices_list);
        if(node == NULL) {
            break;
        }
        struct usb_device *device =
            container_of(node, struct usb_device, match_node);
        res = try_match_pair(driver, device);
        if(res == 0) {
            // No need to re-insert this device into
            // the unmatched list
            continue;
        }
        ilist_push_tail(&unmatched_devices_list, &device->match_node);
    }
    match_lock_release();
    return 0;
}
int
unregister_usb_device_driver(struct usb_device_driver *driver)
{
    match_lock_acquire();
    //ilist_remove(&drivers_list, &driver->match_node);
    match_lock_release();
    return -EUNIMPL;
}

