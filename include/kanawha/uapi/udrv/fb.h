#ifndef __KANAWHA__UAPI_UDRV_FB_H__
#define __KANAWHA__UAPI_UDRV_FB_H__

#include <kanawha/uapi/fb.h>

#define UDRV_FB_PKT_PROVIDE_MODE_INFO (1) // User -> Kernel
struct udrv_fb_pkt_provide_mode_info
{
    unsigned long index;
    struct fb_mode_info mode_info;
};
#define UDRV_FB_PKT_REVOKE_MODE_INFO  (2) // User -> Kernel
struct udrv_fb_pkt_revoke_mode_info
{
    unsigned long index;
};

#define UDRV_FB_PKT_SET_MODE (3)     // Kernel -> User
struct udrv_fb_pkt_set_mode
{
    unsigned long mode;
};
#define UDRV_FB_PKT_CURRENT_MODE (4) // User -> Kernel
struct udrv_fb_pkt_current_mode
{
    unsigned long mode;
};

#define UDRV_FB_PKT_WRITE_TO_BUFFER (5) // Kernel -> User
struct udrv_fb_pkt_write_to_buffer
{
    unsigned long offset;
    unsigned long datalen;
    char data[];
};

#endif
