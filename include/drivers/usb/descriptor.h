#ifndef __KANAWHA__USB_DESCRIPTOR__
#define __KANAWHA__USB_DESCRIPTOR__

#include <drivers/usb/device.h>
#include <kanawha/endian.h>

#define USB_DESCRIPTOR_TYPE_DEVICE (1)
#define USB_DESCRIPTOR_TYPE_CONFIGURATION (2)
#define USB_DESCRIPTOR_TYPE_STRING (3)
#define USB_DESCRIPTOR_TYPE_INTERFACE (4)
#define USB_DESCRIPTOR_TYPE_ENDPOINT (7)
#define USB_DESCRIPTOR_TYPE_INTERFACE_POWER (8)
#define USB_DESCRIPTOR_TYPE_OTG (9)
#define USB_DESCRIPTOR_TYPE_DEBUG (10)
#define USB_DESCRIPTOR_TYPE_INTERFACE_ASSOCIATION (11)
#define USB_DESCRIPTOR_TYPE_BOS (15)
#define USB_DESCRIPTOR_TYPE_DEVICE_CAPABILITY (16)
#define USB_DESCRIPTOR_TYPE_SS_USB_ENDPOINT_COMPANION (48)
#define USB_DESCRIPTOR_TYPE_SS_ISOCH_ENDPOINT_COMPANION (49)

int
usb_device_read_descriptor(struct usb_device *device,
                           int dci,
                           uint8_t type,
                           uint8_t index,
                           void *buffer,
                           size_t buflen);

struct usb_descriptor_device {
    uint8_t bLength;
    uint8_t bDescriptorType;
    le16_t bcdUSB;
    uint8_t bDeviceClass;
    uint8_t bDeviceSubClass;
    uint8_t bDeviceProtocol;
    uint8_t bMaxPacketSize;
    le16_t idVendor;
    le16_t idProduct;
    le16_t bcdDevice;
    uint8_t iManufacturer;
    uint8_t iProduct;
    uint8_t iSerialNumber;
    uint8_t bNumConfigurations;
} __packed;

struct usb_descriptor_configuration {
    uint8_t bLength;
    uint8_t bDescriptorType;
    le16_t wTotalLength;
    uint8_t bNumInterfaces;
    uint8_t bConfigurationValue;
    uint8_t iConfiguration;
    uint8_t bmAttributes;
    uint8_t bMaxPower;
} __packed;

struct usb_descriptor_interface {
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint8_t bInterfaceNumber;
    uint8_t bAlternateSetting;
    uint8_t bNumEndpoints;
    uint8_t bInterfaceClass;
    uint8_t bInterfaceSubClass;
    uint8_t bInterfaceProtocol;
    uint8_t iInterface;
} __packed;

struct usb_descriptor_string_lang {
    uint8_t bLength;
    uint8_t bDescriptorType;
    le16_t wLANGID[];
} __packed;

struct usb_descriptor_string {
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint8_t bString[];
} __packed;

struct usb_descriptor_endpoint {
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint8_t bEndpointAddress;
    uint8_t bmAttributes;
    le16_t wMaxPacketSize;
    uint8_t bInterval;
} __packed;

#endif
