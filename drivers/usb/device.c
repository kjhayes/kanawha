
#include <drivers/usb/device.h>
#include <drivers/usb/descriptor.h>
#include <kanawha/dma.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>

int
usb_host_init_device(struct usb_device *device, struct usb_device_ops *ops)
{
    int res;

    device->ops = ops;

    struct usb_descriptor_device desc;

    printk("Getting USB Device Descriptor...\n");
    res = usb_device_read_descriptor(device,
                                    1,
                                    USB_DESCRIPTOR_TYPE_DEVICE,
                                    0,
                                    &desc,
                                    sizeof(desc));
    if(res)
    {
        wprintk("Failed to get device descriptor! (err=%s)\n", errnostr(res));
        return res;
    }

    if(desc.bDescriptorType != USB_DESCRIPTOR_TYPE_DEVICE) {
        wprintk("USB Device descriptor had invalid type!\n");
        return -EINVAL;
    }


    printk("USB Device: Class=%d, Subclass=%d, Protocol=%d, #Configurations=%d\n",
          (int)desc.bDeviceClass,
          (int)desc.bDeviceSubClass,
          (int)desc.bDeviceProtocol,
          (int)desc.bNumConfigurations
          );

    for(int conf_i = 0; conf_i < desc.bNumConfigurations; conf_i++) {
        struct usb_descriptor_configuration c_desc;
        res = usb_device_read_descriptor(
                device,
                1,
                USB_DESCRIPTOR_TYPE_CONFIGURATION,
                conf_i,
                &c_desc,
                sizeof(c_desc));
        if(res) {
            wprintk("USB Device: Failed to read configuration %d!\n", conf_i);
            continue;
        }

        if(c_desc.bDescriptorType != USB_DESCRIPTOR_TYPE_CONFIGURATION) {
            wprintk("USB Device: Configuration %d descriptor has invalid type!\n",
                    conf_i);
            continue;
        }

        printk("\tConfiguration %d: #Interfaces=%d\n",
                conf_i,
                (int)c_desc.bNumInterfaces);
    }

    return 0;
}

int
usb_host_deinit_device(struct usb_device *device)
{
    return 0;
}

int
usb_device_control_transfer(struct usb_device *device,
                            int dci,
                            uint8_t bmRequestType,
                            uint8_t bRequest,
                            uint16_t wValue,
                            uint16_t wIndex,
                            uint16_t wLength,
                            void __phys *buffer,
                            size_t bufsize)
{
    int res;
    struct usb_transfer *xfer;
    xfer = usb_device_create_control_transfer(
            device,
            dci,
            bmRequestType,
            bRequest,
            wValue,
            wIndex,
            wLength,
            buffer,
            bufsize);
    if(xfer == NULL) {
        return -ENOMEM;
    }

    res = usb_transfer_launch(xfer);
    if(res) {
        usb_device_destroy_transfer(device, xfer);
        return res;
    }

    res = usb_transfer_await(xfer);
    if(res) {
        usb_device_destroy_transfer(device, xfer);
        return res;
    }

    usb_device_destroy_transfer(device, xfer);

    return 0;
}

