
#include <drivers/usb/usb.h>
#include <drivers/usb/device.h>
#include <kanawha/list.h>
#include <kanawha/lock.h>

static DECLARE_ILIST(device_drivers_list);
static DECLARE_ILIST(interface_drivers_list);
static DECLARE_ILIST(unmatched_devices_list);
static DECLARE_ILIST(unmatched_interfaces_list);
DEFINE_LOCAL_THREAD_LOCK(device_match_lock);
DEFINE_LOCAL_THREAD_LOCK(interface_match_lock);

static int
try_match_device(
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

    if(chosen_config > device->num_configs) {
        eprintk("USB device driver requested non-existant configuration %d! (num_configs=%d)\n",
                (int)chosen_config,
                (int)device->num_configs);
        return -EINVAL;
    }

    uint16_t config_value = device->configs[chosen_config].value;

    res = usb_device_control_transfer(
            device,
            USB_ENDPOINT_ID_DEFAULT_CONTROL,
            USB_DEV_CONTROL_REQUEST_TYPE_DIR_HOST_TO_DEVICE
           |USB_DEV_CONTROL_REQUEST_TYPE_TARGET_DEVICE
           |USB_DEV_CONTROL_REQUEST_TYPE_STANDARD,
            USB_DEV_CONTROL_REQUEST_SET_CONFIGURATION,
            config_value,
            0,
            0,
            NULL,
            0);
    if(res) {
        wprintk("Failed to configure USB device! (err=%s)\n",
                errnostr(res));
        return res;
    }


    res = usb_device_driver_init_device(driver, device);
    if(res) {
        return res;
    }

    ilist_push_tail(&driver->matched_devices, &device->match_node);
    device->driver = driver;

    return 0;
}

static int
try_match_interface(
        struct usb_interface_driver *driver,
        struct usb_interface *interface)
{
    int res;

    res = usb_interface_driver_probe(driver, interface);
    if(res) {
        return res;
    }

    res = usb_interface_driver_init(driver, interface);
    if(res) {
        return res;
    }

    ilist_push_tail(&driver->matched_interfaces, &interface->match_node);
    interface->driver = driver;

    return 0;
}

int
register_usb_device(struct usb_device *device)
{
    int res;
    int matched = 0;

    device->driver = NULL;

    device_match_lock_acquire();
    ilist_node_t *driver_iter;
    ilist_for_each(driver_iter, &device_drivers_list) {
        struct usb_device_driver *driver =
            container_of(driver_iter, struct usb_device_driver, match_node);
        res = try_match_device(driver, device);
        if(res == 0) {
            matched = 1;
            break;
        }
    }

    if(!matched) {
        ilist_push_tail(&unmatched_devices_list, &device->match_node);
    }
    device_match_lock_release();
    return 0;
}
int
unregister_usb_device(struct usb_device *device)
{
    device_match_lock_acquire();
    //ilist_remove(&unmatched_devices_list, &device->match_node);
    device_match_lock_release();
    return -EUNIMPL;
}

int
register_usb_interface(struct usb_interface *interface)
{
    int res;
    int matched = 0;

    interface->driver = NULL;

    interface_match_lock_acquire();

    ilist_node_t *driver_iter;
    ilist_for_each(driver_iter, &interface_drivers_list)
    {
        struct usb_interface_driver *driver =
            container_of(driver_iter, struct usb_interface_driver, match_node);
        res = try_match_interface(driver, interface);
        if(res == 0) {
            matched = 1;
            break;
        }
    }

    if(!matched) {
        ilist_push_tail(
                &unmatched_interfaces_list,
                &interface->match_node);
    }
    interface_match_lock_release();
    return 0;
}
int
unregister_usb_interface(struct usb_interface *interface)
{
    return -EUNIMPL;
}

int
register_usb_device_driver(struct usb_device_driver *driver)
{
    int res;

    ilist_init(&driver->matched_devices);

    device_match_lock_acquire();
    ilist_push_tail(&device_drivers_list, &driver->match_node);
    size_t len = ilist_count(&unmatched_devices_list);
    for(size_t i = 0; i < len; i++) {
        ilist_node_t *node = ilist_pop_head(&unmatched_devices_list);
        if(node == NULL) {
            break;
        }
        struct usb_device *device =
            container_of(node, struct usb_device, match_node);
        res = try_match_device(driver, device);
        if(res == 0) {
            // No need to re-insert this device into
            // the unmatched list
            continue;
        }
        ilist_push_tail(&unmatched_devices_list, &device->match_node);
    }
    device_match_lock_release();
    return 0;
}
int
unregister_usb_device_driver(struct usb_device_driver *driver)
{
    device_match_lock_acquire();
    //ilist_remove(&device_drivers_list, &driver->match_node);
    device_match_lock_release();
    return -EUNIMPL;
}

int
register_usb_interface_driver(struct usb_interface_driver *driver)
{
    int res;

    ilist_init(&driver->matched_interfaces);

    interface_match_lock_acquire();
    ilist_push_tail(&interface_drivers_list, &driver->match_node);
    size_t len = ilist_count(&unmatched_interfaces_list);
    for(size_t i = 0; i < len; i++) {
        ilist_node_t *node = ilist_pop_head(&unmatched_interfaces_list);
        if(node == NULL) {
            break;
        }
        struct usb_interface *device =
            container_of(node, struct usb_interface, match_node);
        res = try_match_interface(driver, device);
        if(res == 0) {
            // No need to re-insert this interface into
            // the unmatched list
            continue;
        }
        ilist_push_tail(&unmatched_interfaces_list, &device->match_node);
    }
    interface_match_lock_release();

    return 0;
}
int
unregister_usb_interface_driver(struct usb_interface_driver *driver)
{
    interface_match_lock_acquire();
    // TODO
    interface_match_lock_release();

    return -EUNIMPL;
}

// Unknown Device Driver

static int
usb_unknown_device_probe(
        struct usb_device_driver *driver,
        struct usb_device *device)
{
    if(device->usb_id.class == 0) {
        return 0;
    }
    return -EINVAL;
}

static int
usb_unknown_device_configure(
        struct usb_device_driver *driver,
        struct usb_device *device,
        size_t *req_config)
{
    printk("usb_unknown_device_configure!\n");
    *req_config = 0;
    return 0;
}

static int
usb_unknown_device_init(
        struct usb_device_driver *driver,
        struct usb_device *device)
{
    printk("usb_unknown_device_init!\n");
    int res;
    for(size_t i = 0; i < device->configs[0].num_interfaces; i++) {
        struct usb_interface *interface = &device->configs[0].interfaces[i];
        res = register_usb_interface(interface);
        if(res) {
            for(size_t j = 0; j < i; j++) {
                unregister_usb_interface(&device->configs[0].interfaces[i]);
            }
            return res;
        }
    }
    return 0;
}

static int
usb_unknown_device_deinit(
        struct usb_device_driver *driver,
        struct usb_device *device)
{
    int res;
    for(size_t i = 0; i < device->configs[0].num_interfaces; i++) {
        struct usb_interface *interface = &device->configs[0].interfaces[i];
        unregister_usb_interface(interface);
    }
    return 0;
}

struct usb_device_driver_ops
usb_unknown_device_driver_ops = {
    .probe_device = usb_unknown_device_probe,
    .configure_device = usb_unknown_device_configure,
    .init_device = usb_unknown_device_init,
    .deinit_device = usb_unknown_device_deinit,
};

static struct usb_device_driver
usb_unknown_device_driver = {
    .ops = &usb_unknown_device_driver_ops,
};

static int
usb_unknown_device_driver_init(void)
{
    return register_usb_device_driver(&usb_unknown_device_driver);
}
declare_init(device, usb_unknown_device_driver_init);
