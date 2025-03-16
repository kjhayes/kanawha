#ifndef __KANAWHA_ARCH_RISCV64_HLIC_H__
#define __KANAWHA_ARCH_RISCV64_HLIC_H__

#include <arch/riscv64/cpu.h>
#include <kanawha/irq.h>
#include <kanawha/irq_dev.h>
#include <devtree/node.h>

struct riscv64_hlic {
    hartid_t hartid;
    struct irq_dev irq_dev;
    struct irq_domain *domain;
};

int
riscv64_setup_cpu_hlic(
        struct riscv64_cpu *cpu,
        struct dt_node *dt_node);

struct irq_desc *
riscv64_hlic_irq_desc(hwirq_t hwirq, cpu_id_t cpu);

#endif
