
#include <kanawha/dev/clk.h>
#include <kanawha/init.h>

static int
clk_dev_init(struct clk_dev *dev)
{
    printk("clk_dev registered: %s\n", clk_dev_get_name(dev));
    return 0;
}

static int
clk_dev_deinit(struct clk_dev *dev)
{
    printk("clk_dev unregistered: %s\n", clk_dev_get_name(dev));
    return 0;
}

DEFINE_DEV_TYPE(clk_dev, dev, clk_dev_init, clk_dev_deinit);

#ifdef CONFIG_LOG_CLKDEV_REGISTRY_ON_LAUNCH
static int
dump_clk_dev_on_launch(void)
{
    return dump_clk_dev_registry(do_printk);
}
declare_init(launch, dump_clk_dev_on_launch);
#endif
