
#include <mb2/info.h>
#include <kanawha/init.h>
#include <kanawha/pointer.h>
#include <kanawha/printk.h>
#include <kanawha/vmem.h>
#include <kanawha/string.h>

static void
mb2_framebuffer_info_handler(
        struct mb2_info *info,
        struct mb2_info_tag *tag,
        void *state)
{
    int *res_ptr = state;

    if(tag->hdr.type == MB2_INFO_TAG_TYPE_FRAMEBUFFER_INFO) {
	void __phys *phys_addr = (void __phys *)tag->fb_info.phys_addr;
	size_t size = tag->fb_info.height * tag->fb_info.pitch;
	printk("Found Multiboot2 Framebuffer at [%p - %p)\n",
		phys_addr,
		phys_addr + size);
	printk("Clearing Multiboot2 Framebuffer to all 1's\n");
	memset_p(phys_addr, 0xFF, size);
    }
}

static int
mb2_find_framebuffer(void)
{
    int res = 0;

    struct mb2_info **info_ptr = (void*)__va((void __phys *)&boot_mb2_info_ptr);
    struct mb2_info *info = (void*)__va((void __phys *)*info_ptr);

    mb2_info_for_each_tag(
            info,
            mb2_framebuffer_info_handler,
            &res);

    return res;
}

declare_init_desc(device, mb2_find_framebuffer, "Looking for Framebuffer from Multiboot2 Info");

