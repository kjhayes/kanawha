
#include <mb2/info.h>
#include <kanawha/printk.h>
#include <kanawha/errno.h>
#include <kanawha/init.h>
#include <kanawha/vmem.h>
#include <kanawha/ramfile.h>

static inline int
register_module_ramfile(
        struct mb2_info_tag *tag)
{
    uint32_t start = tag->module.mod_start;
    uint32_t end = tag->module.mod_end;
    uint32_t size = end - start;

    int res;

    printk("Creating ramfile \"%s\" from Multiboot2 Module...\n", tag->module.utf8_str);
    res = create_ramfile(
            (const char*)tag->module.utf8_str,
            (paddr_t)start,
            size);

    if(res) {
        return res;
    }

    return 0;
}

static void
mb2_module_handler(
        struct mb2_info *info,
        struct mb2_info_tag *tag,
        void *state)
{
    int *res = state;
    switch(tag->hdr.type) {
        case MB2_INFO_TAG_TYPE_MODULE:
            *res |= register_module_ramfile(tag);
            break;
    }
}

static int
mb2_init_modules_as_ramfile(void)
{
    int res = 0;
    struct mb2_info **info_ptr = (void*)__va((paddr_t)&boot_mb2_info_ptr);
    struct mb2_info *info = (void*)__va((paddr_t)*info_ptr);

    dprintk("info=%p\n", __pa((vaddr_t)info));

    mb2_info_for_each_tag((struct mb2_info*)__va((paddr_t)*(struct mb2_info**)__va((paddr_t)&boot_mb2_info_ptr)), mb2_module_handler, &res); 
    return res;
}

declare_init_desc(early_device, mb2_init_modules_as_ramfile, "Looking for Multiboot2 Modules");

