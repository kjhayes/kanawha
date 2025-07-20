
#include <kanawha/dev/rand.h>
#include <kanawha/init.h>

DEFINE_REGISTRY(
        rand_dev,
        registry_node,
        REGISTRY_NO_INIT_FUNCTION,
        REGISTRY_NO_DEINIT_FUNCTION
        );

#ifdef CONFIG_LOG_RANDDEV_REGISTRY_ON_LAUNCH
static int
dump_rand_dev_on_launch(void) {
    return dump_rand_dev_registry(do_printk);
}
declare_init(launch, dump_rand_dev_on_launch);
#endif
