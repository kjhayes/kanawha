
#include <drivers/usb/id.h>

const char *
usb_id_class_name(struct usb_id *id)
{
    switch(id->class)
    {
    case 0x00:
        return "Interface-Defined";
    case 0x01:
        return "Audio";
    case 0x02:
        return "Communications and CDC Control";
    case 0x03:
        return "Human Interface Device";
    case 0x05:
        return "Physical";
    case 0x06:
        return "Image";
    case 0x07:
        return "Printer";
    case 0x08:
        return "Mass Storage";
    case 0x09:
        return "Hub";
    case 0x0A:
        return "CDC-Data";
    case 0x0B:
        return "Smart Card";
    case 0x0D:
        return "Content Security";
    case 0x0E:
        return "Video";
    case 0x0F:
        return "Personal Healthcare";
    case 0x10:
        return "Audio/Video";
    case 0x11:
        return "Billboard";
    case 0x12:
        return "USB Type-C Bridge";
    case 0x13:
        return "USB Bulk Display Protocol";
    case 0x14:
        return "MCTP over USB Protocol Endpoint Device";
    case 0x3C:
        return "I3C";
    case 0xDC:
        return "Diagnostic";
    case 0xE0:
        return "Wireless Controller";
    case 0xEF:
        return "Miscellaneous";
    case 0xFE:
        return "Application Specific";
    case 0xFF:
        return "Vendor Specific";
    default:
        break;
    }
    return "";
}

const char *
usb_id_subclass_name(struct usb_id *id)
{
    switch(id->class)
    {
    case 0x09:
    {
        switch(id->subclass)
        {
        case 0x00:
            return "Full-Speed";
        case 0x01:
            return "Hi-Speed Single TT";
        case 0x02:
            return "Hi-Speed Multiple TT";
        default:
            break;
        }
    }
    case 0x10:
    {
        switch(id->subclass)
        {
        case 0x00:
            return "AVControl Interface";
        case 0x01:
            return "AVData video Streaming Interface";
        case 0x02:
            return "AVData Audio Streaming Interface";
        default:
            break;
        }
    }
    default:
        break;
    }
    return "";
}

const char *
usb_id_protocol_name(struct usb_id *id)
{
    return "";
}
