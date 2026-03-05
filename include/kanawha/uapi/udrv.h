#ifndef __KANAWHA__UAPI_UDRV_H__
#define __KANAWHA__UAPI_UDRV_H__

struct udrv_pkt
{
    unsigned long type;
    unsigned long flags;
    char data[];
};

#endif
