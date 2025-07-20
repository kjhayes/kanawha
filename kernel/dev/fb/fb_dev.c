
#include <kanawha/dev/fb.h>
#include <kanawha/init.h>

DEFINE_REGISTRY(
        fb_dev,
        registry_node,
        REGISTRY_NO_INIT_FUNCTION,
        REGISTRY_NO_DEINIT_FUNCTION
        );

#ifdef CONFIG_LOG_FBDEV_REGISTRY_ON_LAUNCH
static int
dump_fb_dev_on_launch(void) {
    return dump_fb_dev_registry(do_printk);
}
declare_init(launch, dump_fb_dev_on_launch);
#endif
