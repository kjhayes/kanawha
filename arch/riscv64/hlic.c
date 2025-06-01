
#include <arch/riscv64/hlic.h>
#include <arch/riscv64/cpu.h>
#include <arch/riscv64/trap.h>
#include <arch/riscv64/sbi_ipi.h>
#include <arch/riscv64/csr.h>

#include <kanawha/percpu.h>
#include <kanawha/init.h>
#include <kanawha/lock.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/irq.h>
#include <kanawha/irq_domain.h>
#include <kanawha/irq_dev.h>
#include <kanawha/xcall.h>

#include <devtree/driver.h>
#include <devtree/match.h>

#define HLIC_SSI_HWIRQ 1

DECLARE_PERCPU_VAR(struct irq_domain *, riscv64_hlic_irq_domain);

DEFINE_LOCAL_THREAD_LOCK(riscv64_percpu_hlic_actions_lock);
static struct irq_action *
riscv64_percpu_hlic_actions[RISCV64_INTERRUPT_IRQ_DOMAIN_SIZE] = { 0 };

static irq_t
riscv64_dt_hlic_xlate_irq(
        struct dt_driver *driver,
        struct dt_node *node,
        const fdt32_t *cells,
        size_t cell_count)
{
    if(cell_count != 1) {
        return NULL_IRQ;
    }

    uint32_t value = fdttoh32(*cells);
    hwirq_t hwirq = (hwirq_t)value;

    struct riscv64_hlic *hlic = node->driver_state;

    irq_t irq = irq_domain_revmap(hlic->domain, hwirq);

    return irq;
}

static struct dt_driver_ops
riscv64_dt_hlic_driver_ops = {
    .probe = dt_driver_cannot_probe,
    .init_node = dt_driver_cannot_init_node,
    .deinit_node = dt_driver_cannot_deinit_node,
    .xlate_irq = riscv64_dt_hlic_xlate_irq,
};

static struct dt_driver
riscv64_dt_hlic_driver = {
    .ops = &riscv64_dt_hlic_driver_ops,
    .num_ids = 0,
};

static int
riscv64_hlic_irq_dev_ack_irq(
        struct irq_dev *dev,
        hwirq_t hwirq)
{
    dprintk("riscv64_hlic_irq_dev_ack_irq\n");
    return 0;
}

static int
riscv64_hlic_irq_dev_eoi_irq(
        struct irq_dev *dev,
        hwirq_t hwirq)
{
    dprintk("riscv64_hlic_irq_dev_eoi_irq\n");
    return 0;
}

static int
riscv64_hlic_irq_dev_mask_irq(
        struct irq_dev *dev,
        hwirq_t hwirq)
{
    struct riscv64_hlic *hlic = container_of(dev, struct riscv64_hlic, irq_dev);
    if(hlic->hartid != current_hartid()) {
        // TODO, we could place an X-Call if we really wanted to
        return -EINVAL;
    }

    uint64_t sie = read_csr(sie);
    sie &= ~(1ULL<<hwirq);
    write_csr(sie, sie);

    return 0;
}

static int
riscv64_hlic_irq_dev_unmask_irq(
        struct irq_dev *dev,
        hwirq_t hwirq)
{
    dprintk("riscv64_hlic_irq_dev_unmask_irq\n");

    switch(hwirq) {
        case 1:
        case 5:
        case 9:
            break;
        default:
            return -EINVAL;
    }

    uint64_t sie = read_csr(sie);
    sie |= (1ULL<<hwirq);
    write_csr(sie, sie);

    return 0;
}

static unsigned long
riscv64_hlic_irq_dev_irq_status(
        struct irq_dev *dev,
        hwirq_t hwirq)
{
    switch(hwirq) {
        case 1:
        case 5:
        case 9:
            break;
        default:
            return IRQ_STATUS_INVALID;
    }

    unsigned long flags = 0;
    uint64_t sie = read_csr(sie);
    if(!(sie & (1ULL<<hwirq))) {
        flags |= IRQ_STATUS_MASKED;
    }

    return flags;
}


static int
riscv64_hlic_irq_dev_trigger_irq(
        struct irq_dev *dev,
        hwirq_t hwirq)
{
    dprintk("riscv64_hlic_irq_dev_trigger_irq\n");
    if(hwirq != HLIC_SSI_HWIRQ) {
        return -EINVAL;
    }

    struct riscv64_hlic *hlic = container_of(dev, struct riscv64_hlic, irq_dev);
    hartid_t hartid = hlic->hartid;

    return sbi_send_ipi(hartid);
}

static struct irq_dev_driver
riscv64_hlic_irq_dev_driver = {
    .ack_irq = riscv64_hlic_irq_dev_ack_irq,
    .eoi_irq = riscv64_hlic_irq_dev_eoi_irq,
    .mask_irq = riscv64_hlic_irq_dev_mask_irq,
    .unmask_irq = riscv64_hlic_irq_dev_unmask_irq,
    .irq_status = riscv64_hlic_irq_dev_irq_status,
    .trigger_irq = riscv64_hlic_irq_dev_trigger_irq,
    .describe_irq = irq_dev_default_describe_irq,
};

int
riscv64_setup_cpu_hlic(
        struct riscv64_cpu *cpu,
        struct dt_node *hlic_node)
{
    int res;

    struct riscv64_hlic *hlic = kmalloc(sizeof(struct riscv64_hlic));
    if(hlic == NULL) {
        return -ENOMEM;
    }
    memset(hlic, 0, sizeof(*hlic));

    hlic->hartid = cpu_id_to_hartid(cpu->cpu.id);

    struct irq_domain *hlic_domain;
    hlic_domain = alloc_irq_domain_linear(0, RISCV64_INTERRUPT_IRQ_DOMAIN_SIZE);
    if(hlic_domain == NULL) {
        eprintk("Failed to allocate IRQ domain for CPU %lu HLIC!\n", cpu->cpu.id);
        kfree(cpu);
        return res;
    }

    hlic->irq_dev.driver = &riscv64_hlic_irq_dev_driver;
    res = irq_domain_set_all_irq_dev(hlic_domain, &hlic->irq_dev);
    if(res) {
        free_irq_domain_linear(hlic_domain);
        kfree(cpu);
        return res;
    }

    hlic->domain = hlic_domain;
    *(struct irq_domain**)percpu_ptr_specific(percpu_addr(riscv64_hlic_irq_domain), cpu->cpu.id) = hlic_domain;


    riscv64_percpu_hlic_actions_lock_acquire();
    for(size_t i = 0; i < RISCV64_INTERRUPT_IRQ_DOMAIN_SIZE; i++)
    {    
        irq_t hlic_irq = irq_domain_revmap(hlic_domain, i);
        if(hlic_irq == NULL_IRQ) {
            eprintk("Failed to get HLIC IRQ!\n");
            continue;
        }
        struct irq_desc *hlic_desc = irq_to_desc(hlic_irq);
        if(hlic_desc == NULL) {
            eprintk("Failed to get HLIC IRQ descriptor!\n");
            continue;
        }

        struct irq_action *action;
        if(riscv64_percpu_hlic_actions[i] == NULL) {
            struct irq_desc *irq_desc = riscv64_interrupt_irq_desc((hwirq_t)i);
            if(irq_desc == NULL) {
                eprintk("Failed to get descriptor of RISCV IRQ %lu!\n", i);
                continue;
            }
            action = irq_install_percpu_link(irq_desc);
            if(action == NULL) {
                eprintk("Failed to install percpu link from RISCV IRQ %lu to HLIC IRQ!\n",
                        i);
                continue;
            }
            riscv64_percpu_hlic_actions[i] = action;
        } else {
            action = riscv64_percpu_hlic_actions[i];
        }

        res = irq_action_set_percpu_link(
                action,
                hlic_desc,
                cpu->cpu.id);
        if(res) {
            eprintk("Failed to create percpu link from RISCV IRQ to HLIC IRQ on CPU %lu\n",
                    (ul_t)cpu->cpu.id);
            riscv64_percpu_hlic_actions_lock_release();
            return res;
        }
    }
    riscv64_percpu_hlic_actions_lock_release();

    res = dt_driver_claim_node(&riscv64_dt_hlic_driver, hlic_node);
    if(res) {
        eprintk("Failed to claim HLIC device tree node for CPU %lu\n", (ul_t)cpu->cpu.id);
        return res;
    }
    hlic_node->driver_state = hlic;

    return 0;
}

static int
riscv64_hlic_provide_xcall_ipis(void)
{
    int res;

    for(cpu_id_t id = 0; id < total_num_cpus(); id++)
    {
        struct irq_domain *hlic_domain =
            *(struct irq_domain**)percpu_ptr_specific(percpu_addr(riscv64_hlic_irq_domain), id);
        irq_t ipi_irq = irq_domain_revmap(hlic_domain, HLIC_SSI_HWIRQ);
        printk("Providing HLIC IPI IRQ(%lu) on CPU (%lu)\n",
                (ul_t)ipi_irq,
                (ul_t)id);

        res = xcall_provide_ipi_irq(id, irq_domain_revmap(hlic_domain, HLIC_SSI_HWIRQ));
        if(res) {
            eprintk("Failed to provide X-CALL IPI from HLIC on CPU(%lu) (err=%s)\n",
                    (ul_t)id,
                    errnostr(res));
            return res;
        }
    }

    return 0;
}
declare_init_desc(smp, riscv64_hlic_provide_xcall_ipis, "Providing HLIC IPI(s) to X-CALL Framework");

struct irq_desc *
riscv64_hlic_irq_desc(hwirq_t hwirq, cpu_id_t cpu)
{
    struct irq_domain *domain = *(struct irq_domain **)percpu_ptr_specific(percpu_addr(riscv64_hlic_irq_domain), cpu);
    DEBUG_ASSERT(KERNEL_ADDR(domain));
    if(domain == NULL) {
        return NULL;
    }

    irq_t irq = irq_domain_revmap(domain, hwirq);
    if(irq == NULL_IRQ) {
        return NULL;
    }

    return irq_to_desc(irq);
}

static int
riscv64_register_hlic_dt_driver(void) {
    int res;
    res = register_dt_driver_nomatch(&riscv64_dt_hlic_driver);
    if(res) {
        return res;
    }
    return 0;
}
declare_init(dynamic, riscv64_register_hlic_dt_driver);

