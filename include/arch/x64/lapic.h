#ifndef __KANAWHA__X64_LAPIC_H__
#define __KANAWHA__X64_LAPIC_H__

#include <kanawha/stdint.h>
#include <kanawha/device.h>
#include <kanawha/irq_dev.h>
#include <kanawha/ops.h>

#define LAPIC_BASE_ADDR_MSR 0x0000001B
#define LAPIC_BASE_ADDR_MSR_BSP         (1ULL<<8)
#define LAPIC_BASE_ADDR_MSR_APIC_ENABLE (1ULL<<11)

// These are all defined using xAPIC offsets
// x2APIC will need to translate to MSR(s)
#define LAPIC_REG_ID      0x20
#define LAPIC_REG_VERSION 0x30
#define LAPIC_REG_TPR 0x80
#define LAPIC_REG_APR 0x90
#define LAPIC_REG_PPR 0xA0
#define LAPIC_REG_EOI 0xB0
#define LAPIC_REG_RRD 0xC0
#define LAPIC_REG_LDR 0xD0
#define LAPIC_REG_DFR 0xE0
#define LAPIC_REG_SIV 0xF0
#define LAPIC_REG_ISR0 0x100
#define LAPIC_REG_ISR1 0x110
#define LAPIC_REG_ISR2 0x120
#define LAPIC_REG_ISR3 0x130
#define LAPIC_REG_ISR4 0x140
#define LAPIC_REG_ISR5 0x150
#define LAPIC_REG_ISR6 0x160
#define LAPIC_REG_ISR7 0x170
#define LAPIC_REG_TMR0 0x180
#define LAPIC_REG_TMR1 0x190
#define LAPIC_REG_TMR2 0x1A0
#define LAPIC_REG_TMR3 0x1B0
#define LAPIC_REG_TMR4 0x1C0
#define LAPIC_REG_TMR5 0x1D0
#define LAPIC_REG_TMR6 0x1E0
#define LAPIC_REG_TMR7 0x1F0
#define LAPIC_REG_IRR0 0x200
#define LAPIC_REG_IRR1 0x210
#define LAPIC_REG_IRR2 0x220
#define LAPIC_REG_IRR3 0x230
#define LAPIC_REG_IRR4 0x240
#define LAPIC_REG_IRR5 0x250
#define LAPIC_REG_IRR6 0x260
#define LAPIC_REG_IRR7 0x270
#define LAPIC_REG_ESR 0x280
#define LAPIC_REG_LVT_CMCI 0x2F0 // Intel Only
#define LAPIC_REG_ICR 0x300
#define LAPIC_REG_ICR_LOW  0x300
#define LAPIC_REG_ICR_HIGH 0x310 // xAPIC Only
#define LAPIC_REG_LVT_TIMER   0x320
#define LAPIC_REG_LVT_THERMAL 0x330
#define LAPIC_REG_LVT_PERF    0x340
#define LAPIC_REG_LVT_LINT0   0x350
#define LAPIC_REG_LVT_LINT1   0x360
#define LAPIC_REG_LVT_ERROR   0x370
#define LAPIC_REG_TMR_ICR 0x380
#define LAPIC_REG_TMR_CCR 0x390
#define LAPIC_REG_TMR_DCR 0x3E0

#define LAPIC_MT_FIXED        0b000
#define LAPIC_MT_LOW_PRIORITY 0b001
#define LAPIC_MT_SMI          0b010
#define LAPIC_MT_REMOTE_READ  0b011
#define LAPIC_MT_NMI          0b100
#define LAPIC_MT_INIT         0b101
#define LAPIC_MT_STARTUP      0b110
#define LAPIC_MT_EXTINT       0b111

#define LAPIC_TRIGGER_MODE_EDGE  0
#define LAPIC_TRIGGER_MODE_LEVEL 1

enum {
    LAPIC_LVT_TIMER_HWIRQ = 0,
    LAPIC_LVT_THERMAL_HWIRQ,
    LAPIC_LVT_PERF_HWIRQ,
    LAPIC_LVT_LINT0_HWIRQ,
    LAPIC_LVT_LINT1_HWIRQ,
    LAPIC_LVT_ERROR_HWIRQ,
    LAPIC_LVT_CMCI_HWIRQ,
};



struct x64_cpu;

typedef uint32_t apic_id_t;

/*
 * APIC Accesses assume that we are accessing the LAPIC
 * of the current processor (and hence preemption is disabled somehow)
 */

#define LAPIC_READ_REG_SIG(RET,ARG)\
RET(uint64_t)\
ARG(size_t, reg)

#define LAPIC_WRITE_REG_SIG(RET,ARG)\
RET(int)\
ARG(size_t, reg)\
ARG(uint64_t, val)

#define LAPIC_READ_ID_SIG(RET,ARG)\
RET(apic_id_t)

#define LAPIC_SEND_IPI_SIG(RET,ARG)\
RET(int)\
ARG(apic_id_t, target)\
ARG(uint8_t, vector)\
ARG(int, message_type)\
ARG(int, logical)\
ARG(int, assert)\
ARG(int, trigger_mode)\

#define LAPIC_OP_LIST(OP, ...)\
OP(read_reg, LAPIC_READ_REG_SIG, ##__VA_ARGS__)\
OP(write_reg, LAPIC_WRITE_REG_SIG, ##__VA_ARGS__)\
OP(read_id, LAPIC_READ_ID_SIG, ##__VA_ARGS__)\
OP(send_ipi, LAPIC_SEND_IPI_SIG, ##__VA_ARGS__)\

struct lapic;
struct lapic_ops {
DECLARE_OP_LIST_PTRS(LAPIC_OP_LIST, struct lapic *)
};

struct lapic {
    struct device device;

    struct lapic_ops *ops;
    apic_id_t id;

    struct irq_dev irq_dev; // IDT IRQ Vector Controller
    struct irq_domain *irq_domain;

    struct irq_dev lvt_dev; // Local Vector Table IRQ Controller
    struct irq_domain *lvt_domain;
};

DEFINE_OP_LIST_WRAPPERS(
        LAPIC_OP_LIST,
        static inline,
        /* No Prefix */,
        lapic,
        ->ops->,
        SELF_ACCESSOR)

#undef LAPIC_READ_REG_SIG
#undef LAPIC_WRITE_REG_SIG
#undef LAPIC_OP_LIST

int
bsp_register_cpu_lapic(
        struct x64_cpu *cpu);

int
lapic_init_current(void);

irq_t
lapic_vector_irq(cpu_id_t cpu, hwirq_t vector);

irq_t
lapic_lvt_irq(cpu_id_t cpu, hwirq_t lvt_index);

#endif
