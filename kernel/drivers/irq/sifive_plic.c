
#include <kanawha/init.h>
#include <devtree/devtree.h>
#include <devtree/driver.h>
#include <devtree/match.h>

#include <kanawha/irq_dev.h>
#include <kanawha/irq_domain.h>
#include <kanawha/mmio.h>
#include <kanawha/kmalloc.h>

struct sifive_plic
{
    struct irq_dev irq_dev;

    void __phys *phys_base;
    void __mmio *mmio_base;
    size_t mmio_size;

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

    printk("Found SiFive PLIC with 0x%lx Interrupts\n", (ul_t)irq_count);

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
declare_init_desc(dynamic, register_sifive_plic_driver, "Registering SiFive PLIC Driver");

