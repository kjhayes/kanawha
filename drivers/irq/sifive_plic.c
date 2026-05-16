
#include <devtree/devtree.h>
#include <devtree/driver.h>
#include <devtree/match.h>
#include <kanawha/init.h>

#include <kanawha/dev/irq.h>
#include <kanawha/irq_domain.h>
#include <kanawha/kmalloc.h>
#include <kanawha/mmio.h>

struct sifive_plic_context
{
    struct sifive_plic *plic;
    irq_t irq;
    struct irq_action *action;

    void __mmio *enable_bitmap;
    void __mmio *reg_block;
};

struct sifive_plic
{
    struct irq_dev irq_dev;

    void __phys *phys_base;
    void __mmio *mmio_base;
    size_t mmio_size;

    size_t num_irqs;

    size_t ctx_count;
    struct sifive_plic_context *contexts;

    struct irq_domain *irq_domain;
};

static hwirq_t
sifive_plic_context_claim(struct sifive_plic_context *ctx)
{
    uint32_t value = mmio_readl(ctx->reg_block + 4);
    return (hwirq_t)value;
}

static void
sifive_plic_context_complete(struct sifive_plic_context *ctx, hwirq_t hwirq)
{
    mmio_writel(ctx->reg_block + 4, (uint32_t)hwirq);
}

static int
sifive_plic_ctx_irq_handler(struct excp_state *excp_state,
                            struct irq_action *action)
{
    int res;

    struct sifive_plic_context *ctx = action->handler_data.priv_data;
    DEBUG_ASSERT(KERNEL_ADDR(ctx));
    struct sifive_plic *plic = ctx->plic;
    DEBUG_ASSERT(KERNEL_ADDR(plic));

    hwirq_t hwirq;
    hwirq = sifive_plic_context_claim(ctx);
    if(hwirq == 0)
    {
        return IRQ_NONE;
    }

    irq_t irq;
    irq = irq_domain_revmap(plic->irq_domain, hwirq);
    if(irq == IRQ_NONE)
    {
        sifive_plic_context_complete(ctx, hwirq);
        return IRQ_UNHANDLED;
    }

    struct irq_desc *desc = irq_to_desc(irq);
    if(desc == NULL)
    {
        sifive_plic_context_complete(ctx, hwirq);
        return IRQ_UNHANDLED;
    }

    res = handle_irq(desc, excp_state);

    sifive_plic_context_complete(ctx, hwirq);

    return res;
}

static int
sifive_plic_context_set_priority(struct sifive_plic_context *ctx,
                                 uint32_t priority)
{
    mmio_writel(ctx->reg_block + 0, priority);
    return 0;
}

static int
sifive_plic_set_hwirq_priority(struct sifive_plic *plic,
                               hwirq_t hwirq,
                               uint32_t priority)
{
    mmio_writel(plic->mmio_base + (4 * hwirq), priority);
    return 0;
}

static int
sifive_plic_mask_irq(struct irq_dev *irq_dev, hwirq_t hwirq)
{
    int res;

    struct sifive_plic *plic =
        container_of(irq_dev, struct sifive_plic, irq_dev);
    if(hwirq >= plic->num_irqs)
    {
        return -EINVAL;
    }

    res = sifive_plic_set_hwirq_priority(plic, hwirq, 0);
    if(res)
    {
        // This should be fine... but unexpected
        wprintk("sifive_plic_mask_irq: failed to set hwirq priority to zero! "
                "(weird)\n");
    }

    for(size_t i = 0; i < plic->ctx_count; i++)
    {
        struct sifive_plic_context *ctx = &plic->contexts[i];

        if(ctx->irq != NULL_IRQ)
        {
            size_t offset = hwirq / 32;
            size_t bit = hwirq % 32;
            uint32_t bits =
                mmio_readl(((uint32_t *)ctx->enable_bitmap) + offset);
            bits &= ~(1ULL << bit);
            mmio_writel(((uint32_t *)ctx->enable_bitmap) + offset, bits);
        }
    }
    return 0;
}

static int
sifive_plic_unmask_irq(struct irq_dev *irq_dev, hwirq_t hwirq)
{
    int res;

    dprintk("plic_unmask_irq %d\n",
            (int)hwirq);

    struct sifive_plic *plic =
        container_of(irq_dev, struct sifive_plic, irq_dev);
    if(hwirq >= plic->num_irqs)
    {
        return -EINVAL;
    }

    res = sifive_plic_set_hwirq_priority(plic, hwirq, 1);
    if(res)
    {
        return res;
    }

    for(size_t i = 0; i < plic->ctx_count; i++)
    {
        struct sifive_plic_context *ctx = &plic->contexts[i];

        if(ctx->irq != NULL_IRQ)
        {
            size_t offset = hwirq / 32;
            size_t bit = hwirq % 32;
            uint32_t bits = mmio_readl(((uint32_t*)ctx->enable_bitmap) + offset);
            bits |= (1ULL << bit);
            mmio_writel(((uint32_t*)ctx->enable_bitmap) + offset, bits);
        }
    }
    return 0;
}

static int
sifive_plic_ack_irq(struct irq_dev *irq_dev, hwirq_t hwirq)
{
    // Everything is routed into our IRQ handler
    // which does ACK/EOI
    return 0;
}
static int
sifive_plic_eoi_irq(struct irq_dev *irq_dev, hwirq_t hwirq)
{
    // Everything is routed into our IRQ handler
    // which does ACK/EOI
    return 0;
}
static unsigned long
sifive_plic_irq_status(struct irq_dev *irq_dev, hwirq_t hwirq)
{
    return IRQ_STATUS_UNKNOWN;
}
int
sifive_plic_trigger_irq(struct irq_dev *irq_dev, hwirq_t hwirq)
{
    return -EUNIMPL;
}

static int
sifive_plic_describe_irq(
        struct irq_dev *irq_dev,
        hwirq_t hwirq,
        char *buffer,
        size_t buflen)
{
    snprintk(buffer, buflen,
            "plic-%lu",
            (ul_t)hwirq);
    return 0;
}

static struct irq_driver sifive_plic_irq_driver = {
    .ack_irq = sifive_plic_ack_irq,
    .eoi_irq = sifive_plic_eoi_irq,
    .mask_irq = sifive_plic_mask_irq,
    .unmask_irq = sifive_plic_unmask_irq,
    .irq_status = sifive_plic_irq_status,
    .trigger_irq = sifive_plic_trigger_irq,
    .describe_irq = sifive_plic_describe_irq,
};

static int
sifive_plic_dt_probe(struct dt_driver *driver, struct dt_node *node)
{
    size_t reg_count = dt_node_reg_count(node);
    if(reg_count != 1)
    {
        return -EINVAL;
    }
    return 0;
}

static int
sifive_plic_dt_init(struct dt_driver *driver, struct dt_node *node)
{
    int res;

    struct sifive_plic *plic = kmalloc(sizeof(struct sifive_plic), KM_KERNEL);
    if(plic == NULL)
    {
        return -ENOMEM;
    }
    memset(plic, 0, sizeof(struct sifive_plic));

    plic->irq_dev.driver = &sifive_plic_irq_driver;

    res = dt_node_read_reg(node, 1, &plic->phys_base, &plic->mmio_size);
    if(res)
    {
        kfree(plic);
        return res;
    }

    plic->mmio_base = mmio_map(plic->phys_base, plic->mmio_size);
    if(plic->mmio_base == NULL)
    {
        kfree(plic);
        return -ENOMEM;
    }

    uint32_t irq_count;
    res = dt_node_read_property_u32(node, "riscv,ndev", &irq_count);
    if(res)
    {
        mmio_unmap(plic->mmio_base, plic->mmio_size);
        kfree(plic);
        return res;
    }

    plic->num_irqs = irq_count;

    plic->irq_domain = alloc_irq_domain_linear(1, irq_count);
    if(plic->irq_domain == NULL)
    {
        mmio_unmap(plic->mmio_base, plic->mmio_size);
        kfree(plic);
        return res;
    }

    size_t ctx_count;
    res = dt_node_irq_count(node, &ctx_count);
    if(res)
    {
        mmio_unmap(plic->mmio_base, plic->mmio_size);
        free_irq_domain_linear(plic->irq_domain);
        kfree(plic);
        return res;
    }

    if(ctx_count < 1)
    {
        wprintk("Found SiFive PLIC without any contexts!\n");
    }

    printk("Found SiFive PLIC with 0x%lx Interrupts and 0x%lx Contexts\n",
           (ul_t)irq_count,
           (ul_t)ctx_count);

    plic->ctx_count = ctx_count;
    plic->contexts =
        kmalloc(sizeof(struct sifive_plic_context) * ctx_count, KM_KERNEL);
    if(plic->contexts == NULL)
    {
        mmio_unmap(plic->mmio_base, plic->mmio_size);
        free_irq_domain_linear(plic->irq_domain);
        kfree(plic);
        return -ENOMEM;
    }
    // Default everything to NULL
    for(size_t i = 0; i < plic->ctx_count; i++)
    {
        plic->contexts[i].irq = NULL_IRQ;
    }

    // Actually initialize each context
    for(size_t i = 0; i < plic->ctx_count; i++)
    {
        irq_t irq;
        res = dt_node_read_irq(node, i, &irq);
        if(res)
        {
            panic("Failed to read IRQ for PLIC context %lu! (err=%s)\n",
                  (ul_t)i,
                  errnostr(res));
        }

        plic->contexts[i].irq = irq;
        plic->contexts[i].plic = plic;

        if(irq == NULL_IRQ)
        {
            plic->contexts[i].reg_block = NULL;
            plic->contexts[i].enable_bitmap = NULL;
            plic->contexts[i].action = NULL;
            printk("SiFive PLIC Context(%lu) Does Not Exist\n", (ul_t)i);
        }
        else
        {

            struct irq_desc *parent_desc = irq_to_desc(irq);
            if(parent_desc == NULL)
            {
                panic("Failed to get IRQ descriptor for PLIC "
                      "context %lu!\n",
                      (ul_t)i);
            }

            size_t enable_bitmap_offset = 0x2000ull + (i * 0x80ull);
            if(enable_bitmap_offset >= plic->mmio_size)
            {
                panic(
                    "sifive_plic: enable_bitmap_offset >= plic->mmio_size!\n");
            }
            size_t reg_block_offset = 0x200000ull + (i * 0x1000ull);
            if(reg_block_offset >= plic->mmio_size)
            {
                panic("sifive_plic: reg_block_offset >= plic->mmio_size!\n");
            }

            plic->contexts[i].enable_bitmap =
                plic->mmio_base + enable_bitmap_offset;
            plic->contexts[i].reg_block = plic->mmio_base + reg_block_offset;
            plic->contexts[i].action =
                irq_install_handler(parent_desc,
                                    &plic->contexts[i],
                                    sifive_plic_ctx_irq_handler);
            if(plic->contexts[i].action == NULL)
            {
                panic("Failed to install PLIC IRQ handler!\n");
            }
            printk("SiFive PLIC Context(%lu) IRQ=0x%lx\n", (ul_t)i, (ul_t)irq);
            res = unmask_irq(irq);
            if(res)
            {
                panic("Failed to unmask IRQ for PLIC Context(%lu) (err=%s)\n",
                      (ul_t)i,
                      errnostr(res));
            }

            sifive_plic_context_set_priority(&plic->contexts[i], 0);
        }
    }

    // TODO handle errors
    register_irq_dev(&plic->irq_dev, "sifive-plic");

    // TODO handle errors
    irq_domain_set_all_irq_dev(plic->irq_domain, &plic->irq_dev);

    node->driver_state = plic;

    return 0;
}

static int
sifive_plic_dt_deinit(struct dt_driver *driver, struct dt_node *node)
{
    printk("sifive_plic_deinit\n");
    return -EUNIMPL;
}

static irq_t
sifive_plic_dt_xlate_irq(struct dt_driver *driver,
                         struct dt_node *node,
                         const fdt32_t *cells,
                         size_t cell_count)
{
    if(cell_count != 1)
    {
        wprintk("sifive_plic cannot translate hwirq with "
                "more than 1 cell! (cells=%d)\n",
                (s_t)cell_count);
        return NULL_IRQ;
    }
    hwirq_t hwirq = fdttoh32(cells[0]);

    struct sifive_plic *plic = node->driver_state;
    irq_t irq = irq_domain_revmap(plic->irq_domain, hwirq);

    printk("sifive_plic_xlate_irq hwirq(%ld) -> irq(%ld)\n",
           (sl_t)hwirq,
           (sl_t)irq);

    return irq;
}

struct dt_driver_ops sifive_plic_dt_driver_ops = {
    .probe = sifive_plic_dt_probe,
    .init_node = sifive_plic_dt_init,
    .deinit_node = sifive_plic_dt_deinit,
    .xlate_irq = sifive_plic_dt_xlate_irq,
    .xlate_irq_map = dt_driver_xlate_irq_map_no_address,
};

struct dt_node_id sifive_plic_dt_ids[] = {{.compatible = "sifive,plic-1.0.0"}};

struct dt_driver sifive_plic_dt_driver = {
    .num_ids = sizeof(sifive_plic_dt_ids) / sizeof(struct dt_node_id),
    .ids = sifive_plic_dt_ids,
    .ops = &sifive_plic_dt_driver_ops,
};

static int
register_sifive_plic_driver(void)
{
    int res;
    res = register_dt_driver(&sifive_plic_dt_driver);
    if(res)
    {
        return res;
    }
    return 0;
}
declare_init_desc(post_topo,
                  register_sifive_plic_driver,
                  "Registering SiFive PLIC Driver");
