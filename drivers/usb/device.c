
#include <drivers/usb/device.h>
#include <kanawha/dma.h>
#include <kanawha/string.h>
#include <kanawha/kmalloc.h>

int
usb_host_register_device(
        struct usb_device *device,
        struct usb_device_ops *ops)
{
    int res;

    device->ops = ops;
    printk("usb_host_register_device\n");

    char desc[8];

    res = usb_device_get_descriptor(
            device,
            1,
            USB_DESCRIPTOR_TYPE_DEVICE,
            0,
            desc,
            8);
    if(res) {
        wprintk("Failed to get device descriptor! (err=%s)\n",
                errnostr(res));
	return res;
    }

    printk("Descriptor= 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n",
            (unsigned)desc[0],
            (unsigned)desc[1],
            (unsigned)desc[2],
            (unsigned)desc[3],
            (unsigned)desc[4],
            (unsigned)desc[5],
            (unsigned)desc[6],
            (unsigned)desc[7]);

    return 0;
}

int
usb_host_deregister_device(
        struct usb_device *device)
{
    return 0;
}


int
usb_device_control_transfer(
        struct usb_device *device,
        int dci,
        uint8_t bmRequestType,
        uint8_t bRequest,
        uint16_t wValue,
        uint16_t wIndex,
        uint16_t wLength,
        void __phys *buffer,
        size_t buflen)
{
    int res;
    int trt;
    int data_dir;
    int status_dir;
    if(bmRequestType & (1<<7)) {
        // Device to Host
        trt = USB_SETUP_STAGE_TRT_IN;
        data_dir = USB_DATA_STAGE_DIR_IN;
        status_dir = USB_STATUS_STAGE_DIR_IN;
    } else {
        // Host to Device
        trt = USB_SETUP_STAGE_TRT_OUT;
        data_dir = USB_DATA_STAGE_DIR_OUT;
        status_dir = USB_STATUS_STAGE_DIR_OUT;
    }

    printk("USB Status Stage\n");

    struct usb_transfer *setup;
    setup = usb_device_create_setup_stage_transfer(
            device,
            dci,
            bmRequestType,
            bRequest,
            wValue,
            wIndex,
            wLength,
            trt);
    if(setup == NULL) {
        return -EINVAL;
    }

    res = usb_transfer_launch(setup);
    if(res) {
	wprintk("Failed to launch USB setup stage transfer (err=%s)\n", errnostr(res));
	usb_device_destroy_transfer(device, setup);
	return res;
    }
    res = usb_transfer_await(setup);
    if(res) {
	wprintk("Failed to await USB setup stage transfer (err=%s)\n", errnostr(res));
	usb_device_destroy_transfer(device, setup);
	return res;
    }

    usb_device_destroy_transfer(device, setup);

    printk("USB Data Stage\n");

    struct usb_transfer *data;
    data = usb_device_create_data_stage_transfer(
            device,
            dci,
            buffer,
            buflen,
            data_dir);
    if(data == NULL) {
        return -EINVAL;
    }

    res = usb_transfer_launch(data);
    if(res) {
	wprintk("Failed to launch USB data stage transfer (err=%s)\n", errnostr(res));
	usb_device_destroy_transfer(device, data);
	return res;
    }
    res = usb_transfer_await(data);
    if(res) {
	wprintk("Failed to await USB data stage transfer (err=%s)\n", errnostr(res));
	usb_device_destroy_transfer(device, data);
	return res;
    }

    usb_device_destroy_transfer(device, data);

    printk("USB Status Stage\n");

    struct usb_transfer *status;
    status = usb_device_create_status_stage_transfer(
            device,
            dci,
            status_dir);
    if(status == NULL) {
        return -EINVAL;
    }

    res = usb_transfer_launch(status);
    if(res) {
	wprintk("Failed to launch USB status stage transfer (err=%s)\n", errnostr(res));
	usb_device_destroy_transfer(device, status);
	return res;
    }
    res = usb_transfer_await(status);
    if(res) {
	wprintk("Failed to await USB status stage transfer (err=%s)\n", errnostr(res));
	usb_device_destroy_transfer(device, status);
	return res;
    }

    usb_device_destroy_transfer(device, status);

    return 0;
}

int
usb_device_get_descriptor(
        struct usb_device *device,
        int dci,
        uint8_t type,
        uint8_t index,
        void *buffer,
        size_t buflen)
{
    int res;

    uint16_t wValue = ((uint16_t)type << 8) | index;
    uint16_t wIndex = 0; // "or Language ID"
    uint16_t wLength = buflen;

    dma_addr_t dma_buffer;
    res = dma_alloc(buflen, 16, DMA_PHYS_64, &dma_buffer);
    if(res) {
        return res;
    }

    void __phys *phys_buffer = dma_phys_addr(dma_buffer);

    res = usb_device_control_transfer(
            device,
            dci,
            USB_DEV_CONTROL_REQUEST_TYPE_TARGET_DEVICE|
            USB_DEV_CONTROL_REQUEST_TYPE_DIR_DEVICE_TO_HOST|
            USB_DEV_CONTROL_REQUEST_TYPE_STANDARD,
            USB_DEV_CONTROL_REQUEST_GET_DESCRIPTOR,
            wValue,
            wIndex,
            wLength,
            phys_buffer,
            buflen);
    if(res) {
        return res;
    }

    void *dma_virt = dma_virt_addr(dma_buffer);
    memcpy(buffer, dma_virt, buflen);

    dma_free(dma_buffer, buflen);

    return 0;
}

