
#include <kanawha/dev/rand.h>
#include <kanawha/init.h>

static int
rand_dev_init(struct rand_dev *dev)
{
    waitqueue_init(&dev->read_wq);
    waitqueue_name(&dev->read_wq, rand_dev_get_name(dev));
    printk("rand_dev registered: %s\n", rand_dev_get_name(dev));
    return 0;
}

static int
rand_dev_deinit(struct rand_dev *dev)
{
    waitqueue_deinit(&dev->read_wq);
    printk("rand_dev unregistered: %s\n", rand_dev_get_name(dev));
    return 0;
}

DEFINE_DEV_TYPE(rand_dev, dev, rand_dev_init, rand_dev_deinit);

#ifdef CONFIG_LOG_RANDDEV_REGISTRY_ON_LAUNCH
static int
dump_rand_dev_on_launch(void)
{
    return dump_rand_dev_registry(do_printk);
}
declare_init(launch, dump_rand_dev_on_launch);
#endif
