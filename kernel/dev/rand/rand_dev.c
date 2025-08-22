
#include <kanawha/dev/rand.h>
#include <kanawha/init.h>

static int
rand_dev_init(struct rand_dev *dev)
{
    waitqueue_init(&dev->read_wq);
    return 0;
}

static int
rand_dev_deinit(struct rand_dev *dev)
{
    waitqueue_deinit(&dev->read_wq);
    return 0;
}

DEFINE_REGISTRY(
        rand_dev,
        registry_node,
        rand_dev_init,
        rand_dev_deinit 
        );

#ifdef CONFIG_LOG_RANDDEV_REGISTRY_ON_LAUNCH
static int
dump_rand_dev_on_launch(void) {
    return dump_rand_dev_registry(do_printk);
}
declare_init(launch, dump_rand_dev_on_launch);
#endif
