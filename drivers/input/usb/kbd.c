
#include <kanawha/init.h>
#include <drivers/usb/usb.h>

static int
usb_kbd_driver_probe_device(
        struct usb_device_driver *driver,
        struct usb_device *device)
{
    printk("usb_kbd_probe!\n");
    return 0;
    return -EUNIMPL;
}

static int
usb_kbd_driver_configure_device(
        struct usb_device_driver *driver,
        struct usb_device *device,
        size_t *config_choice)
{
    printk("usb_kbd_configure!\n");
    return 0;
    return -EUNIMPL;
}

static int
usb_kbd_driver_init_device(
        struct usb_device_driver *driver,
        struct usb_device *device)
{
    printk("usb_kbd_init!\n");
    return 0;
    return -EUNIMPL;
}

static int
usb_kbd_driver_deinit_device(
        struct usb_device_driver *driver,
        struct usb_device *device)
{
    return -EUNIMPL;
}

static struct usb_device_driver_ops
usb_kbd_driver_ops = {
    .probe_device = usb_kbd_driver_probe_device,
    .configure_device = usb_kbd_driver_configure_device,
    .init_device = usb_kbd_driver_init_device,
    .deinit_device = usb_kbd_driver_deinit_device,
};
static struct usb_device_driver
usb_kbd_driver = {
    .ops = &usb_kbd_driver_ops,
};

static int
usb_kbd_driver_register(void)
{
    return register_usb_device_driver(&usb_kbd_driver);
}
declare_init_desc(device, usb_kbd_driver_register, "Registering USB Keyboard Driver");

