
#include <kanawha/printk.h>
#include <kanawha/errno.h>
#include <kanawha/init.h>
#include <kanawha/vmem.h>
#include <kanawha/ramfile.h>

static int
vga_framebuffer_as_ramfile(void)
{
    int res = 0;

    res = create_ramfile(
            "vga-fb",
            (void __phys *)0xb8000,
            2 * 80 * 25);
    if(res) {
        return res;
    }

    return 0;
}

declare_init_desc(early_device, vga_framebuffer_as_ramfile, "Presenting VGA Framebuffer as a Ramfile Device");

