
#include <kanawha/init.h>
#include <drivers/usb/usb.h>
#include <drivers/usb/device.h>

static int
usb_hid_driver_probe_interface(
        struct usb_interface_driver *driver,
        struct usb_interface *interface)
{
    printk("usb_hid_probe!\n");
    if(interface->usb_id.class != 0x3) {
        return -EINVAL;
    }
    return 0;
    return -EUNIMPL;
}

static int
usb_hid_driver_init_interface(
        struct usb_interface_driver *driver,
        struct usb_interface *interface)
{
    printk("usb_hid_init!\n");
    return 0;
    return -EUNIMPL;
}

static int
usb_hid_driver_deinit_interface(
        struct usb_interface_driver *driver,
        struct usb_interface *interface)
{
    return -EUNIMPL;
}

static struct usb_interface_driver_ops
usb_hid_driver_ops = {
    .probe = usb_hid_driver_probe_interface,
    .init = usb_hid_driver_init_interface,
    .deinit = usb_hid_driver_deinit_interface,
};
static struct usb_interface_driver
usb_hid_driver = {
    .ops = &usb_hid_driver_ops,
};

static int
usb_hid_driver_register(void)
{
    return register_usb_interface_driver(&usb_hid_driver);
}
declare_init_desc(device, usb_hid_driver_register, "Registering USB HID Driver");

