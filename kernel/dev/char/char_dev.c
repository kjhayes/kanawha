
#include <kanawha/dev/char.h>
#include <kanawha/init.h>

DEFINE_REGISTRY(
        char_dev,
        registry_node,
        REGISTRY_NO_INIT_FUNCTION,
        REGISTRY_NO_DEINIT_FUNCTION);

#ifdef CONFIG_LOG_CHARDEV_REGISTRY_ON_LAUNCH
static int
dump_char_dev_on_launch(void) {
    return dump_char_dev_registry(do_printk);
}
declare_init(launch, dump_char_dev_on_launch);
#endif

