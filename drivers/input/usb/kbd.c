
#include <kanawha/init.h>
#include <drivers/usb/usb.h>

static int
usb_kbd_driver_probe_interface(
        struct usb_interface_driver *driver,
        struct usb_interface *interface)
{
    printk("usb_kbd_probe!\n");
    return 0;
    return -EUNIMPL;
}

static int
usb_kbd_driver_init_interface(
        struct usb_interface_driver *driver,
        struct usb_interface *interface)
{
    printk("usb_kbd_init!\n");
    return 0;
    return -EUNIMPL;
}

static int
usb_kbd_driver_deinit_interface(
        struct usb_interface_driver *driver,
        struct usb_interface *interface)
{
    return -EUNIMPL;
}

static struct usb_interface_driver_ops
usb_kbd_driver_ops = {
    .probe = usb_kbd_driver_probe_interface,
    .init = usb_kbd_driver_init_interface,
    .deinit = usb_kbd_driver_deinit_interface,
};
static struct usb_interface_driver
usb_kbd_driver = {
    .ops = &usb_kbd_driver_ops,
};

static int
usb_kbd_driver_register(void)
{
    return register_usb_interface_driver(&usb_kbd_driver);
}
declare_init_desc(device, usb_kbd_driver_register, "Registering USB Keyboard Driver");

