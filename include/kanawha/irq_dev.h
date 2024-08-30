#ifndef __KANAWHA__IRQ_DEV_H__
#define __KANAWHA__IRQ_DEV_H__

#include <kanawha/irq.h>
#include <kanawha/stdint.h>
#include <kanawha/cpu.h>
#include <kanawha/ops.h>

struct irq_dev;
struct irq_dev_driver;

#define IRQ_DEV_MASK_IRQ_SIG(RET,ARG)\
RET(int)\
ARG(hwirq_t, hwirq)

#define IRQ_DEV_UNMASK_IRQ_SIG(RET,ARG)\
RET(int)\
ARG(hwirq_t, hwirq)

#define IRQ_DEV_ACK_IRQ_SIG(RET,ARG)\
RET(int)\
ARG(hwirq_t, to_ack)

#define IRQ_DEV_EOI_IRQ_SIG(RET,ARG)\
RET(int)\
ARG(hwirq_t, to_eoi)

#define IRQ_DEV_TRIGGER_IRQ_SIG(RET,ARG)\
RET(int)\
ARG(hwirq_t, irq)

#define IRQ_DEV_OP_LIST(OP, ...)\
OP(mask_irq, IRQ_DEV_MASK_IRQ_SIG, ##__VA_ARGS__)\
OP(unmask_irq, IRQ_DEV_UNMASK_IRQ_SIG, ##__VA_ARGS__)\
OP(ack_irq, IRQ_DEV_ACK_IRQ_SIG, ##__VA_ARGS__)\
OP(eoi_irq, IRQ_DEV_EOI_IRQ_SIG, ##__VA_ARGS__)\
OP(trigger_irq, IRQ_DEV_TRIGGER_IRQ_SIG, ##__VA_ARGS__)\

struct irq_dev_driver {
DECLARE_OP_LIST_PTRS(IRQ_DEV_OP_LIST, struct irq_dev*)
};

struct irq_dev {
    struct irq_dev_driver *driver;
    struct device *device;
};

DEFINE_OP_LIST_WRAPPERS(
        IRQ_DEV_OP_LIST,
        static inline,
        /* No Prefix */,
        irq_dev,
        ->driver->,
        SELF_ACCESSOR)

#undef IRQ_DEV_OP_LIST
#undef IRQ_DEV_MASK_IRQ_SIG
#undef IRQ_DEV_UNMASK_IRQ_SIG

#endif
