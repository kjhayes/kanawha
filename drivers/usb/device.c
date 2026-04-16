
#include <drivers/usb/device.h>
#include <drivers/usb/descriptor.h>
#include <kanawha/dma.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>

static int
usb_host_init_device_configurations(
        struct usb_device *device)
{
    int res;

    // We assume that the number of configurations
    // is valid, and that the array has been allocated for
    // us
    DEBUG_ASSERT(device->num_configs > 0);
    DEBUG_ASSERT(KERNEL_ADDR(device->configs));

    for(size_t ci = 0; ci < device->num_configs; ci++)
    {
        struct usb_configuration *config = &device->configs[ci];

        config->device = device;

        struct usb_descriptor_configuration c_desc;
        res = usb_device_read_descriptor(
                device,
                USB_ENDPOINT_ID_DEFAULT_CONTROL,
                USB_DESCRIPTOR_TYPE_CONFIGURATION,
                ci,
                &c_desc,
                sizeof(c_desc));
        if(res) {
            wprintk("USB Device: Failed to read configuration %d!\n",
                    (int)ci);
            continue;
        }

        if(c_desc.bDescriptorType != USB_DESCRIPTOR_TYPE_CONFIGURATION) {
            wprintk("USB Device: Configuration %d descriptor has invalid type!\n",
                    (int)ci);
            continue;
        }

        size_t full_desc_len = letoh16(c_desc.wTotalLength);
        void *buffer = kzmalloc(full_desc_len, KM_KERNEL);
        if(buffer == NULL) {
            continue;
        }

        res = usb_device_read_descriptor(
                device,
                USB_ENDPOINT_ID_DEFAULT_CONTROL,
                USB_DESCRIPTOR_TYPE_CONFIGURATION,
                ci,
                buffer,
                full_desc_len);
        if(res) {
            kfree(buffer);
            wprintk("USB Device: Configuration %d Failed to Read Full Descriptor! (err=%s)\n",
                    (int)ci, errnostr(res));
            config->num_interfaces = 0;
            config->interfaces = NULL;
            continue;
        }

        config->value = c_desc.bConfigurationValue;
        config->num_interfaces = c_desc.bNumInterfaces;

        printk("\tConfiguration %d: #Interfaces=%d\n",
                (int)ci,
                (int)config->num_interfaces);

        config->interfaces = kzmalloc(
                sizeof(struct usb_interface) *
                config->num_interfaces,
                KM_KERNEL);
        if((config->interfaces == NULL) && (config->num_interfaces > 0)) {
            config->num_interfaces = 0;
                wprintk("Failed to allocate buffer for USB device configuration interface info!\n");
            continue;
        }

        void *iter = buffer + sizeof(struct usb_descriptor_configuration);
        for(size_t ii = 0; ii < config->num_interfaces; ii++)
        {
            struct usb_interface *interface = &config->interfaces[ii];

            interface->config = config;

            struct usb_descriptor_interface *i_desc = iter;
            iter += i_desc->bLength;

            interface->num_interface_endpoints = i_desc->bNumEndpoints;
            interface->usb_id.class = i_desc->bInterfaceClass;
            interface->usb_id.subclass = i_desc->bInterfaceSubClass;
            interface->usb_id.protocol = i_desc->bInterfaceProtocol;

            printk("\t\tInterface %d: id=%d.%d.%d %s %s %s #Endpoints=%d\n",
                    (int)ii,
                    (int)interface->usb_id.class,
                    (int)interface->usb_id.subclass,
                    (int)interface->usb_id.protocol,
                    usb_id_class_name(&interface->usb_id),
                    usb_id_subclass_name(&interface->usb_id),
                    usb_id_protocol_name(&interface->usb_id),
                    (int)interface->num_interface_endpoints);

            interface->interface_endpoints = kzmalloc(
                    sizeof(struct usb_interface_endpoint) *
                    interface->num_interface_endpoints,
                    KM_KERNEL);
            if((interface->interface_endpoints == NULL) && (interface->num_interface_endpoints > 0)) {
                interface->num_interface_endpoints = 0;
                wprintk("Failed to allocate buffer for USB device interface endpoint info!\n");
                continue;
            }

            for(size_t ei = 0; ei < interface->num_interface_endpoints; ei++) {
                struct usb_interface_endpoint *endpoint = &interface->interface_endpoints[ei];
                struct usb_descriptor_endpoint *e_desc = iter;
                iter += e_desc->bLength;

                uint8_t endpoint_num = (e_desc->bEndpointAddress & 0xF);
                uint8_t endpoint_dir = (e_desc->bEndpointAddress >> 7) & 1;

                

                endpoint->max_packet_size = letoh16(e_desc->wMaxPacketSize);

                printk("\t\t\tEndpoint %d: EP#=%d dir=%s\n",
                        (int)ei,
                        (int)endpoint->endpoint.endpoint_number,
                        endpoint->endpoint.direction ? "IN" : "OUT");
            }
        }


        kfree(buffer);
    }

    return 0;
}

int
usb_host_init_device(struct usb_device *device, struct usb_device_ops *ops)
{
    int res;

    device->ops = ops;
    device->configured = 0;
    device->num_configs = 0;
    device->configs = NULL;

    struct usb_descriptor_device desc;

    printk("Getting USB Device Descriptor...\n");
    res = usb_device_read_descriptor(device,
                                    USB_ENDPOINT_ID_DEFAULT_CONTROL,
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

    device->usb_id.class = desc.bDeviceClass;
    device->usb_id.subclass = desc.bDeviceSubClass;
    device->usb_id.protocol = desc.bDeviceProtocol;
    device->num_configs = desc.bNumConfigurations;

    printk("USB Device: id=%d.%d.%d %s %s %s #Configurations=%d\n",
          (int)device->usb_id.class,
          (int)device->usb_id.subclass,
          (int)device->usb_id.protocol,
          usb_id_class_name(&device->usb_id),
          usb_id_subclass_name(&device->usb_id),
          usb_id_protocol_name(&device->usb_id),
          (int)device->num_configs
          );


    if(device->num_configs > 0) {
        device->configs = kzmalloc(sizeof(struct usb_configuration) * device->num_configs, KM_KERNEL);
        if(device->configs == NULL) {
            return -ENOMEM;
        }
        res = usb_host_init_device_configurations(device);
        if(res) {
            return res;
        }
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
                            usb_endpoint_id_t endpoint,
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
            endpoint,
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

