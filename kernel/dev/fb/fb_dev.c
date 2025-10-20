
#include <kanawha/dev/fb.h>
#include <kanawha/init.h>

static int
fb_dev_init(struct fb_dev *dev)
{
    printk("fb_dev registered: %s\n", fb_dev_get_name(dev));
    return 0;
}

static int
fb_dev_deinit(struct fb_dev *dev)
{
    printk("fb_dev unregistered: %s\n", fb_dev_get_name(dev));
    return 0;
}

DEFINE_REGISTRY(
        fb_dev,
        registry_node,
	fb_dev_init,
	fb_dev_deinit
        );

#ifdef CONFIG_LOG_FBDEV_REGISTRY_ON_LAUNCH
static int
dump_fb_dev_on_launch(void) {
    return dump_fb_dev_registry(do_printk);
}
declare_init(launch, dump_fb_dev_on_launch);
#endif
