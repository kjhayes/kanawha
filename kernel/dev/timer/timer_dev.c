
#include <kanawha/dev/timer.h>
#include <kanawha/init.h>

static int
timer_dev_init(struct timer_dev *dev)
{
    printk("timer_dev registered: %s\n", timer_dev_get_name(dev));
    return 0;
}

static int
timer_dev_deinit(struct timer_dev *dev)
{
    printk("timer_dev unregistered: %s\n", timer_dev_get_name(dev));
    return 0;
}

DEFINE_DEV_TYPE(timer_dev, dev, timer_dev_init, timer_dev_deinit);

#ifdef CONFIG_LOG_TIMERDEV_REGISTRY_ON_LAUNCH
static int
dump_timer_dev_on_launch(void)
{
    return dump_timer_dev_registry(do_printk);
}
declare_init(launch, dump_timer_dev_on_launch);
#endif

