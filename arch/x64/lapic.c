
#include <arch/x64/lapic.h>
#include <arch/x64/xapic.h>
#include <arch/x64/cpu.h>
#include <arch/x64/exception.h>
#include <arch/x64/msr.h>
#include <arch/x64/cpuid.h>
#include <kanawha/percpu.h>
#include <kanawha/device.h>
#include <kanawha/irq_domain.h>
#include <kanawha/irq_dev.h>
#include <kanawha/stddef.h>
#include <kanawha/printk.h>
#include <kanawha/thread.h>
#include <kanawha/assert.h>

#define LAPIC_MAX_LVT_ENTRIES 7

#define LAPIC_SPURRIOUS_VECTOR 255
#define LAPIC_LVT_VECTOR_BASE  255-LAPIC_MAX_LVT_ENTRIES

static
struct irq_action *
x64_vector_lapic_actions[256-32] = { 0 };

static int
lapic_device_read_name(
        struct device *device,
        char *buf,
        size_t buf_size)
{
    struct lapic *lapic =
        container_of(device, struct lapic, device);

    snprintk(buf, buf_size, "lapic-%lx", (unsigned long)lapic->id);
    return 0;
}

static struct lapic *
current_lapic(void) {
    struct cpu *gen_cpu = cpu_from_id(current_cpu_id());
    struct x64_cpu *cpu = container_of(gen_cpu, struct x64_cpu, cpu);
    return &cpu->apic;
}

static struct device_ops
lapic_device_ops = {
    .read_name = lapic_device_read_name,
};

static size_t lapic_hwirq_to_lvt_reg[] = 
{
    [LAPIC_LVT_TIMER_HWIRQ] = LAPIC_REG_LVT_TIMER,
    [LAPIC_LVT_THERMAL_HWIRQ] = LAPIC_REG_LVT_THERMAL,
    [LAPIC_LVT_PERF_HWIRQ] = LAPIC_REG_LVT_PERF,
    [LAPIC_LVT_LINT0_HWIRQ] = LAPIC_REG_LVT_LINT0,
    [LAPIC_LVT_LINT1_HWIRQ] = LAPIC_REG_LVT_LINT1,
    [LAPIC_LVT_ERROR_HWIRQ] = LAPIC_REG_LVT_ERROR,
    [LAPIC_LVT_CMCI_HWIRQ] = LAPIC_REG_LVT_CMCI,
};

static int
lapic_lvt_mask_irq(
        struct irq_dev *dev,
        hwirq_t hwirq)
{
    dprintk("lapic_lvt_mask_irq hwirq=0x%x\n", hwirq);
    size_t reg = lapic_hwirq_to_lvt_reg[hwirq];
    struct lapic *apic =
        container_of(dev, struct lapic, lvt_dev);
    if(apic_id_from_cpu(cpu_from_id(current_cpu_id())) != apic->id) {
        return -EINVAL;
    }
    uint64_t lvt = lapic_read_reg(apic, reg);
    lvt |= (1ULL<<16);
    lapic_write_reg(apic, reg, lvt);
    return 0;
}

static int
lapic_lvt_unmask_irq(
        struct irq_dev *dev,
        hwirq_t hwirq)
{
    dprintk("lapic_lvt_unmask_irq hwirq=0x%x\n", hwirq);
    size_t reg = lapic_hwirq_to_lvt_reg[hwirq];
    struct lapic *apic =
        container_of(dev, struct lapic, lvt_dev);
    if(apic_id_from_cpu(cpu_from_id(current_cpu_id())) != apic->id) {
        return -EINVAL;
    }
    uint64_t lvt = lapic_read_reg(apic, reg);
    lvt &= ~(1ULL<<16);
    lapic_write_reg(apic, reg, lvt);
    return 0;
}

static int
lapic_ack_irq(
        struct irq_dev *dev,
        hwirq_t hwirq)
{
    dprintk("lapic vector ack\n");
    return 0;
}

static int
lapic_eoi_irq(
        struct irq_dev *dev,
        hwirq_t hwirq)
{
    dprintk("lapic vector eoi\n");
    struct lapic *apic =
        container_of(dev, struct lapic, irq_dev);

    lapic_write_reg(apic, LAPIC_REG_EOI, 0);
    return 0;
}

static int
lapic_trigger_irq(
        struct irq_dev *dev,
        hwirq_t hwirq)
{
    int res;

    struct lapic *target_apic =
        container_of(dev, struct lapic, irq_dev);

    if(hwirq > 255 || hwirq < 32) {
        return -EINVAL;
    }

    struct lapic *current_apic = current_lapic();

    res = lapic_send_ipi(
            current_apic,
            target_apic->id,
            (uint8_t)hwirq,
            LAPIC_MT_FIXED,
            0, // physical APIC ID
            1, // assert
            LAPIC_TRIGGER_MODE_EDGE);

    return res;
}

int
lapic_mask_irq(
        struct irq_dev *dev,
        hwirq_t hwirq)
{
    // We cannot mask these IRQ's
    return -EINVAL;
}

int
lapic_unmask_irq(
        struct irq_dev *dev,
        hwirq_t hwirq)
{
    // They are always unmasked so this is fine
    return 0;
}

static struct irq_dev_driver
lapic_irq_driver = {
    .mask_irq = lapic_mask_irq,
    .unmask_irq = lapic_unmask_irq,
    .trigger_irq = lapic_trigger_irq,
    .ack_irq = lapic_ack_irq,
    .eoi_irq = lapic_eoi_irq,
};

static struct irq_dev_driver
lapic_lvt_irq_driver = {
    .mask_irq = lapic_lvt_mask_irq,
    .unmask_irq = lapic_lvt_unmask_irq,
    .trigger_irq = NULL,
    .eoi_irq = NULL,
    .ack_irq = NULL,
};

static int
setup_lapic_irq_dev(
        struct x64_cpu *cpu,
        struct lapic *apic)
{
    dprintk("Setting up CPU (%d) LAPIC Vector IRQ Domain\n",
            cpu->cpu.id);
    apic->irq_dev.device = &apic->device;
    apic->irq_dev.driver = &lapic_irq_driver;

    apic->irq_domain = alloc_irq_domain_linear(
            32, 256-32);

    if(apic->irq_domain == NULL) {
        return -ENOMEM;
    }

    for(hwirq_t vector = 32; vector < 256; vector++)
    {
        irq_t irq = irq_domain_revmap(apic->irq_domain, vector);
        struct irq_desc *desc = irq_to_desc(irq);
        if(desc == NULL) {
            free_irq_domain_linear(apic->irq_domain);
            return -EINVAL;
        }
        desc->dev = &apic->irq_dev;

        struct irq_action *action = x64_vector_lapic_actions[vector-32];

        irq_t global_vector_irq = irq_domain_revmap(x64_vector_irq_domain, vector);

        if(action == NULL) {
            action = irq_install_percpu_link(irq_to_desc(global_vector_irq));
            if(action == NULL) {
                free_irq_domain_linear(apic->irq_domain);
                return -ENOMEM;
            }
            x64_vector_lapic_actions[vector-32] = action;
        }

        // This means we need to have set up the percpu alloc framework before
        // calling this initialization
        irq_action_set_percpu_link(action, desc, cpu->cpu.id);
    }

    return 0;
}

static int
setup_lapic_lvt_dev(
        struct x64_cpu *cpu,
        struct lapic *apic)
{
    dprintk("Setting up CPU (%d) LAPIC LVT IRQ Domain\n",
            cpu->cpu.id);

    apic->lvt_dev.device = &apic->device;
    apic->lvt_dev.driver = &lapic_lvt_irq_driver;

    apic->lvt_domain = alloc_irq_domain_linear(
            0, LAPIC_MAX_LVT_ENTRIES);

    if(apic->lvt_domain == NULL) {
        return -ENOMEM;
    }

    // We are not certain if we are the processor that owns this LAPIC or not,
    // so we cannot actually do any lapic_read or lapic_write calls here
    for(hwirq_t hwirq = 0; hwirq < LAPIC_MAX_LVT_ENTRIES; hwirq++)
    {
        irq_t irq = irq_domain_revmap(apic->lvt_domain, hwirq);
        struct irq_desc *desc = irq_to_desc(irq);
        if(desc != NULL) {
            desc->dev = &apic->lvt_dev;
        } else {
            eprintk("Failed to get LAPIC IRQ 0x%lx (hwirq=0x%lx)\n",
                    (unsigned long)irq, (unsigned long)hwirq);
            free_irq_domain_linear(apic->lvt_domain);
            return -EINVAL;
        }

        // We got a vector, map it to our handler
        irq_t percpu_vector_irq = irq_domain_revmap(apic->irq_domain, LAPIC_LVT_VECTOR_BASE+hwirq);
        struct irq_desc *vector_desc = irq_to_desc(percpu_vector_irq);

        // This can be a direct link because we should already have a percpu link
        // to each apic->irq_domain IRQ.
        struct irq_action *link = irq_install_direct_link(
                vector_desc,
                desc);
        if(link == NULL) {
            eprintk("Failed to link vector 0x%lx to APIC IRQ 0x%lx (hwirq=0x%lx)\n",
                    (unsigned long)vector_desc->hwirq,
                    (unsigned long)irq,
                    (unsigned long)hwirq);
            free_irq_domain_linear(apic->lvt_domain);
            return -EINVAL;
        }
    }

    return 0;
}

int
lapic_init_current(void)
{
    dprintk("Enabling LAPIC on CPU %d\n", current_cpu_id());
    struct cpu *gen_cpu = cpu_from_id(current_cpu_id());

    if(gen_cpu == NULL) {
        eprintk("Could not get struct cpu of CPU %d!\n", current_cpu_id());
        return -ENXIO;
    }

    struct x64_cpu *cpu = container_of(gen_cpu, struct x64_cpu, cpu);
    struct lapic *apic = &cpu->apic;

    // Enable the APIC
    uint64_t apic_bar = read_msr(LAPIC_BASE_ADDR_MSR);
    apic_bar |= LAPIC_BASE_ADDR_MSR_APIC_ENABLE;
    write_msr(LAPIC_BASE_ADDR_MSR, apic_bar);

    // Set the spurrious interrupt vector

    // Mark the vector as potentially spurrious so we
    // don't log an error if we see it without anyone handling it
    struct irq_desc *spurrious_desc = irq_to_desc(irq_domain_revmap(apic->irq_domain, LAPIC_SPURRIOUS_VECTOR));
    spurrious_desc->flags |= IRQ_DESC_FLAG_SPURRIOUS;

    // Set the spurrious vector and make sure the LAPIC is software enabled
    uint64_t siv = lapic_read_reg(apic, LAPIC_REG_SIV);
    siv |= LAPIC_SPURRIOUS_VECTOR; // Set spurrious interrupt vector
    siv |= (1ULL<<8); // SW Enable the APIC
    siv &= ~(1ULL<<12); // Broadcast EOI
    lapic_write_reg(apic, LAPIC_REG_SIV, siv);

    // Double check that our APIC ID is correct
    apic_id_t apic_id = lapic_read_id(apic);
    if(apic_id != cpu->apic.id) {
        panic("APIC ID Mismatch! CPU %d has multiple APIC ID's (current=0x%x, new=0x%x)\n",
                cpu->cpu.id, cpu->apic.id, apic_id);
    }

    // Set up all of the LVT entries
    dprintk("--- APIC Local Vector Table ---\n");
    uint64_t timer_ctrl = lapic_read_reg(apic, LAPIC_REG_LVT_TIMER);
    timer_ctrl &= ~(0xFF);
    timer_ctrl |= LAPIC_LVT_VECTOR_BASE + LAPIC_LVT_TIMER_HWIRQ;
    timer_ctrl &= ~(1ULL<<15); // edge-triggered
    timer_ctrl |= (1ULL<<16); // masked
    timer_ctrl &= ~(0b111 << 8); // MT fixed
    lapic_write_reg(apic, LAPIC_REG_LVT_TIMER, timer_ctrl);
    dprintk("\tLVT Timer: 0x%lx\n", timer_ctrl);

    uint64_t thermal_ctrl = lapic_read_reg(apic, LAPIC_REG_LVT_THERMAL);
    thermal_ctrl &= ~(0xFF);
    thermal_ctrl |= LAPIC_LVT_VECTOR_BASE + LAPIC_LVT_THERMAL_HWIRQ;
    thermal_ctrl &= ~(1ULL<<15); // edge-triggered
    thermal_ctrl |= (1ULL<<16); // masked
    thermal_ctrl &= ~(0b111 << 8); // MT fixed
    lapic_write_reg(apic, LAPIC_REG_LVT_THERMAL, thermal_ctrl);
    dprintk("\tLVT Thermal: 0x%lx\n", thermal_ctrl);

    uint64_t perf_ctrl = lapic_read_reg(apic, LAPIC_REG_LVT_PERF);
    perf_ctrl &= ~(0xFF);
    perf_ctrl |= LAPIC_LVT_VECTOR_BASE + LAPIC_LVT_PERF_HWIRQ;
    perf_ctrl &= ~(1ULL<<15); // edge-triggered
    perf_ctrl |= (1ULL<<16); // masked
    perf_ctrl &= ~(0b111 << 8); // MT fixed
    lapic_write_reg(apic, LAPIC_REG_LVT_PERF, perf_ctrl);
    dprintk("\tLVT Perf: 0x%lx\n", perf_ctrl);

    uint64_t lint0_ctrl = lapic_read_reg(apic, LAPIC_REG_LVT_LINT0);
    lint0_ctrl &= ~(0xFF);
    lint0_ctrl |= LAPIC_LVT_VECTOR_BASE + LAPIC_LVT_LINT0_HWIRQ;
    lint0_ctrl &= ~(1ULL<<15); // edge-triggered
    lint0_ctrl |= (1ULL<<16); // masked
    lint0_ctrl &= ~(0b111 << 8); // MT fixed
    lapic_write_reg(apic, LAPIC_REG_LVT_LINT0, lint0_ctrl);
    dprintk("\tLVT LINT0: 0x%lx\n", lint0_ctrl);

    uint64_t lint1_ctrl = lapic_read_reg(apic, LAPIC_REG_LVT_LINT1);
    lint1_ctrl &= ~(0xFF);
    lint1_ctrl |= LAPIC_LVT_VECTOR_BASE + LAPIC_LVT_LINT1_HWIRQ;
    lint1_ctrl &= ~(1ULL<<15); // edge-triggered
    lint1_ctrl |= (1ULL<<16); // masked
    lint1_ctrl &= ~(0b111 << 8); // MT fixed
    lapic_write_reg(apic, LAPIC_REG_LVT_LINT1, lint1_ctrl);
    dprintk("\tLVT LINT1: 0x%lx\n", lint1_ctrl);

    uint64_t error_ctrl = lapic_read_reg(apic, LAPIC_REG_LVT_ERROR);
    error_ctrl &= ~(0xFF);
    error_ctrl |= LAPIC_LVT_VECTOR_BASE + LAPIC_LVT_ERROR_HWIRQ;
    error_ctrl &= ~(1ULL<<15); // edge-triggered
    error_ctrl |= (1ULL<<16); // masked
    error_ctrl &= ~(0b111 << 8); // MT fixed
    lapic_write_reg(apic, LAPIC_REG_LVT_ERROR, error_ctrl);
    dprintk("\tLVT Error: 0x%lx\n", error_ctrl);

    lapic_write_reg(apic, LAPIC_REG_ESR, 0); // Clear the Error Status

    // Don't block any interrupts through the TPR
    lapic_write_reg(apic, LAPIC_REG_TPR, 0);



    return 0;
}

int
bsp_register_cpu_lapic(
        struct x64_cpu *cpu)
{
    int res;

    struct lapic *apic = &cpu->apic;

    res = register_device(
            &apic->device,
            &lapic_device_ops,
            &cpu->cpu.device);
    if(res) {
        return res;
    }

    // We will use XAPIC mode for all LAPIC(s) for now
    res = xapic_setup_lapic(apic);
    if(res) {
        return res;
    }

    res = setup_lapic_irq_dev(cpu, apic);
    if(res) {
        return res;
    }

    res = setup_lapic_lvt_dev(cpu, apic);
    if(res) {
        return res;
    }

    return 0;
}

irq_t
lapic_vector_irq(cpu_id_t cpu_id, hwirq_t vector)
{
    struct cpu *gen_cpu = cpu_from_id(cpu_id);
    struct x64_cpu *cpu = container_of(
            gen_cpu, struct x64_cpu, cpu);

    struct lapic *lapic = &cpu->apic;
    DEBUG_ASSERT(lapic->irq_domain);

    return irq_domain_revmap(lapic->irq_domain, vector);
}

irq_t
lapic_lvt_irq(cpu_id_t cpu_id, hwirq_t lvt_index)
{
    struct cpu *gen_cpu = cpu_from_id(cpu_id);
    struct x64_cpu *cpu = container_of(
            gen_cpu, struct x64_cpu, cpu);

    struct lapic *lapic = &cpu->apic;
    DEBUG_ASSERT(lapic->irq_domain);

    return irq_domain_revmap(lapic->lvt_domain, lvt_index);
}

