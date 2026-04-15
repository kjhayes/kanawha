
#include <kanawha/dma.h>
#include <drivers/usb/descriptor.h>

int
usb_device_read_descriptor(struct usb_device *device,
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
    if(res)
    {
        return res;
    }

    void __phys *phys_buffer = dma_phys_addr(dma_buffer);

    res = usb_device_control_transfer(
        device,
        dci,
        USB_DEV_CONTROL_REQUEST_TYPE_TARGET_DEVICE |
        USB_DEV_CONTROL_REQUEST_TYPE_DIR_DEVICE_TO_HOST |
        USB_DEV_CONTROL_REQUEST_TYPE_STANDARD,
        USB_DEV_CONTROL_REQUEST_GET_DESCRIPTOR,
        wValue,
        wIndex,
        wLength,
        phys_buffer,
        buflen);
    if(res)
    {
        return res;
    }

    void *dma_virt = dma_virt_addr(dma_buffer);
    memcpy(buffer, dma_virt, buflen);

    dma_free(dma_buffer, buflen);

    return 0;
}
