#ifndef __KANAWHA__UAPI_UDRV_FB_H__
#define __KANAWHA__UAPI_UDRV_FB_H__

#ifdef KANAWHA_BUILDING_KERNEL
#include <kanawha/uapi/fb.h>
#else
#include <kanawha/fb.h>
#endif

#define UDRV_FB_PKT_PROVIDE_MODE_INFO (1) // User -> Kernel
struct udrv_fb_pkt_provide_mode_info
{
    unsigned long index;
    struct fb_mode_info mode_info;
};
#define UDRV_FB_PKT_REVOKE_MODE_INFO (2) // User -> Kernel
struct udrv_fb_pkt_revoke_mode_info
{
    unsigned long index;
};

#define UDRV_FB_PKT_SET_MODE (3) // Kernel -> User
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

// Userspace is requesting that the kernel not actually flush
// data for some amount of time (the framebuffer is hidden for
// some reason)
#define UDRV_FB_PKT_MASK_WRITES (6) // User -> Kernel

// Tells the kernel to begin sending write calls again
#define UDRV_FB_PKT_UNMASK_WRITES (7) // User -> Kernel

// Tell the kernel that any framedata saved to userspace buffers
// has been lost and must be resent.
#define UDRV_FB_PKT_NOTIFY_DATA_LOST (8) // User -> Kernel

#endif
