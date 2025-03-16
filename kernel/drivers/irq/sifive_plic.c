
#include <kanawha/init.h>
#include <devtree/devtree.h>
#include <devtree/driver.h>
#include <devtree/match.h>

#include <kanawha/irq_dev.h>
#include <kanawha/irq_domain.h>
#include <kanawha/mmio.h>
#include <kanawha/kmalloc.h>

static int
sifive_plic_ctx_irq_handler(
        struct excp_state *excp_state,
        struct irq_action *action)
{
    printk("sifive_plic IRQ!\n");
    struct sifive_plic_context *ctx = action->handler_data.priv_data;
    DEBUG_ASSERT(KERNEL_ADDR(ctx));

    return IRQ_UNHANDLED;
}

struct sifive_plic_context
{
    struct sifive_plic *plic;
    irq_t irq;
    struct irq_action *action;

    void __mmio *mmio_block;
};

struct sifive_plic
{
    struct irq_dev irq_dev;

    void __phys *phys_base;
    void __mmio *mmio_base;
    size_t mmio_size;

    size_t ctx_count;
    struct sifive_plic_context *contexts;

    struct irq_domain *irq_domain;
};

static int
sifive_plic_mask_irq(
        struct irq_dev *irq_dev,
        hwirq_t hwirq)
{
    return -EUNIMPL;
}

static int
sifive_plic_unmask_irq(
        struct irq_dev *irq_dev,
        hwirq_t hwirq)
{
    return -EUNIMPL;
}

static int
sifive_plic_ack_irq(
        struct irq_dev *irq_dev,
        hwirq_t hwirq)
{
    return -EUNIMPL;
}
static int
sifive_plic_eoi_irq(
        struct irq_dev *irq_dev,
        hwirq_t hwirq)
{
    return -EUNIMPL;
}
int
sifive_plic_trigger_irq(
        struct irq_dev *irq_dev,
        hwirq_t hwirq)
{
    return -EUNIMPL;
}

static struct irq_dev_driver
sifive_plic_irq_driver = {
    .ack_irq = sifive_plic_ack_irq,
    .eoi_irq = sifive_plic_eoi_irq,
    .mask_irq = sifive_plic_mask_irq,
    .unmask_irq = sifive_plic_unmask_irq,
    .trigger_irq = sifive_plic_trigger_irq,
};

static int
sifive_plic_dt_probe(
        struct dt_driver *driver,
        struct dt_node *node)
{
    size_t reg_count = dt_node_reg_count(node);
    if(reg_count != 1) {
        return -EINVAL;
    }
    return 0;
}

static int
sifive_plic_dt_init(
        struct dt_driver *driver,
        struct dt_node *node)
{
    int res;

    struct sifive_plic *plic = kmalloc(sizeof(struct sifive_plic));
    if(plic == NULL) {
        return -ENOMEM;
    }
    memset(plic, 0, sizeof(struct sifive_plic));

    plic->irq_dev.driver = &sifive_plic_irq_driver;

    res = dt_node_read_reg(
            node,
            1,
            &plic->phys_base,
            &plic->mmio_size);
    if(res) {
        kfree(plic);
        return res;
    }

    plic->mmio_base = mmio_map(plic->phys_base, plic->mmio_size);
    if(plic->mmio_base == NULL) {
        kfree(plic);
        return -ENOMEM;
    }

    uint32_t irq_count;
    res = dt_node_read_property_u32(
            node,
            "riscv,ndev",
            &irq_count);
    if(res) {
        mmio_unmap(plic->mmio_base, plic->mmio_size);
        kfree(plic);
        return res;
    }

    plic->irq_domain = alloc_irq_domain_linear(0, irq_count);
    if(plic->irq_domain == NULL) {
        mmio_unmap(plic->mmio_base, plic->mmio_size);
        kfree(plic);
        return res;
    }

    size_t ctx_count;
    res = dt_node_irq_count(node, &ctx_count);
    if(res) {
        mmio_unmap(plic->mmio_base, plic->mmio_size);
        free_irq_domain_linear(plic->irq_domain);
        kfree(plic);
        return res;
    }

    if(ctx_count < 1) {
        wprintk("Found SiFive PLIC without any contexts!\n");
    }

    printk("Found SiFive PLIC with 0x%lx Interrupts and 0x%lx Contexts\n", (ul_t)irq_count, (ul_t)ctx_count);

    plic->ctx_count = ctx_count;
    plic->contexts = kmalloc(sizeof(struct sifive_plic_context) * ctx_count);
    if(plic->contexts == NULL) {
        mmio_unmap(plic->mmio_base, plic->mmio_size);
        free_irq_domain_linear(plic->irq_domain);
        kfree(plic);
        return -ENOMEM;
    }
    // Default everything to NULL
    for(size_t i = 0; i < plic->ctx_count; i++) {
        plic->contexts[i].irq = NULL_IRQ;
    }

    // Actually initialize each context
    for(size_t i = 0; i < plic->ctx_count; i++) {
        irq_t irq;
        res = dt_node_read_irq(node, i, &irq);
        if(res) {
            panic("Failed to read IRQ for PLIC context %lu! (err=%s)\n", (ul_t)i, errnostr(res));
        }

        plic->contexts[i].irq = irq;
        plic->contexts[i].plic = plic;

        if(irq == NULL_IRQ) {
            plic->contexts[i].mmio_block = NULL;
            plic->contexts[i].action = NULL;
            printk("SiFive PLIC Context(%lu) Does Not Exist\n", (ul_t)i);
        } else {

            struct irq_desc *parent_desc = irq_to_desc(irq);
            if(parent_desc == NULL) {
                panic("Failed to get IRQ descriptor for PLIC context %lu!\n", (ul_t)i);
            }

            plic->contexts[i].mmio_block = plic->mmio_base + 0x200000ULL + (i * 0x1000ULL);
            plic->contexts[i].action =
                irq_install_handler(
                        parent_desc,
                        &plic->contexts[i],
                        sifive_plic_ctx_irq_handler);
            if(plic->contexts[i].action == NULL) {
                panic("Failed to install PLIC IRQ handler!\n");
            }
            printk("SiFive PLIC Context(%lu) IRQ=0x%lx\n", (ul_t)i, (ul_t)irq);
        }
    }

    return 0;
}

static int
sifive_plic_dt_deinit(
        struct dt_driver *driver,
        struct dt_node *node)
{
    printk("sifive_plic_deinit\n");
    return -EUNIMPL;
}

static irq_t
sifive_plic_dt_xlate_irq(
        struct dt_driver *driver,
        struct dt_node *node,
        const fdt32_t *cells,
        size_t cell_count)
{
    return NULL_IRQ;
}

struct dt_driver_ops
sifive_plic_dt_driver_ops = {
    .probe = sifive_plic_dt_probe,
    .init_node = sifive_plic_dt_init,
    .deinit_node = sifive_plic_dt_deinit,
    .xlate_irq = sifive_plic_dt_xlate_irq,
};

struct dt_node_id
sifive_plic_dt_ids[] = {
    {
        .compatible = "sifive,plic-1.0.0"
    }
};

struct dt_driver
sifive_plic_dt_driver = {
    .num_ids = sizeof(sifive_plic_dt_ids)/sizeof(struct dt_node_id),
    .ids = sifive_plic_dt_ids,
    .ops = &sifive_plic_dt_driver_ops,
};

static int
register_sifive_plic_driver(void) {
    int res;
    res = register_dt_driver(&sifive_plic_dt_driver);
    if(res) {
        return res;
    }
    return 0;
}
declare_init_desc(post_topo, register_sifive_plic_driver, "Registering SiFive PLIC Driver");

