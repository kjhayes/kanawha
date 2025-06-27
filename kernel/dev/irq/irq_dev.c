
#include <kanawha/dev/irq.h>
#include <kanawha/string.h>

DEFINE_DEV_TYPE(irq);

unsigned long
irq_dev_unknown_irq_status(
        struct irq_dev *dev,
        hwirq_t hwirq)
{
    return IRQ_STATUS_UNKNOWN;
}

int
irq_dev_default_describe_irq(
        struct irq_dev *dev,
        hwirq_t hwirq,
        char *buffer,
        size_t buflen)
{
    if(buflen > 0) {
        buffer[0] = '\0';
    }
    return 0;
}

