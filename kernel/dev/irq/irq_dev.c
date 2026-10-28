
#include <kanawha/dev/irq.h>
#include <kanawha/init.h>
#include <kanawha/string.h>

static int
irq_dev_init(struct irq_dev *dev)
{
    printk("irq_dev registered: %s\n", irq_dev_get_name(dev));
    return 0;
}

static int
irq_dev_deinit(struct irq_dev *dev)
{
    // printk("irq_dev unregistered: %s\n", irq_dev_get_name(dev));
    return 0;
}

DEFINE_DEV_TYPE(irq_dev, dev, irq_dev_init, irq_dev_deinit);

unsigned long
irq_dev_unknown_irq_status(struct irq_dev *dev, hwirq_t hwirq)
{
    return IRQ_STATUS_UNKNOWN;
}

int
irq_dev_default_describe_irq(struct irq_dev *dev,
                             hwirq_t hwirq,
                             struct printer *p)
{
    int res;
    const char *name = irq_dev_get_name(dev);
    if(name != NULL) {
        return fmt_print(p, "%s-hwirq-%lu",
                name,
                (ul_t)hwirq);
    } else {
        return 0;
    }
}

#ifdef CONFIG_LOG_IRQDEV_REGISTRY_ON_LAUNCH
static int
dump_irq_dev_on_launch(void)
{
    return dump_irq_dev_registry(do_printk);
}
declare_init(launch, dump_irq_dev_on_launch);
#endif
