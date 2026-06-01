
#include <devtree/devtree.h>
#include <devtree/driver.h>
#include <devtree/match.h>
#include <kanawha/init.h>

#include <kanawha/dev/irq.h>
#include <kanawha/irq_domain.h>
#include <kanawha/kmalloc.h>
#include <kanawha/mmio.h>
#include <kanawha/xcall.h>

#include <arch/arm64/excp.h>
#ifndef CONFIG_ARM64
#error "GICv2 Driver Depends on the ARM64 Architecture!"
#endif

struct gicv2_cpu_interface {
    struct gicv2 *gic;
    void __mmio *gicc_region;
    size_t gicc_region_size;
};

struct gicv2
{
    void __mmio *gicd_region;
    size_t gicd_region_size;
    void __mmio *gicc_region;
    size_t gicc_region_size;

    unsigned security_ext : 1;

    size_t num_sgi;
    size_t num_ppi;
    size_t num_spi;

    struct irq_domain *sgi_domain;
    struct irq_domain *ppi_domain;
    struct irq_domain *spi_domain;

    struct irq_dev irq_dev;

    struct irq_action *root_action;

    unsigned int num_cpu_interfaces;
    struct gicv2_cpu_interface *cpu_interfaces;
};

#define GICV2_GICD_CTLR            (0x0)
#define GICV2_GICD_TYPER           (0x4)
#define GICV2_GICD_IIDR            (0x8)
#define GICV2_GICD_IGROUPR(__n)    (0x80 + ((__n)*4))
#define GICV2_GICD_ISENABLER(__n)  (0x100 + ((__n)*4))
#define GICV2_GICD_ICENABLER(__n)  (0x180 + ((__n)*4))
#define GICV2_GICD_ISPENDR(__n)    (0x200 + ((__n)*4))
#define GICV2_GICD_ICPENDR(__n)    (0x280 + ((__n)*4))
#define GICV2_GICD_ISACTIVER(__n)  (0x300 + ((__n)*4))
#define GICV2_GICD_ICACTIVER(__n)  (0x380 + ((__n)*4))
#define GICV2_GICD_IPRIORITYR(__n) (0x400 + ((__n)*4))
#define GICV2_GICD_ITARGETSR(__n)  (0x800 + ((__n)*4))
#define GICV2_GICD_ICFGR(__n)      (0xC00 + ((__n)*4))
#define GICV2_GICD_NSACR(__n)      (0xE00 + ((__n)*4))
#define GICV2_GICD_SGIR            (0xF00)
#define GICV2_GICD_CPENDSGIR(__n)  (0xF10 + ((__n)*4))
#define GICV2_GICD_SPENDSGIR(__n)  (0xF20 + ((__n)*4))

#define GICV2_GICC_CTLR       (0x0)
#define GICV2_GICC_PMR        (0x4)
#define GICV2_GICC_BPR        (0x8)
#define GICV2_GICC_IAR        (0xC)
#define GICV2_GICC_EOIR       (0x10)
#define GICV2_GICC_RPR        (0x14)
#define GICV2_GICC_HPPIR      (0x18)
#define GICV2_GICC_ABPR       (0x1C)
#define GICV2_GICC_AIAR       (0x20)
#define GICV2_GICC_AEOIR      (0x24)
#define GICV2_GICC_AHPPIR     (0x28)
#define GICV2_GICC_APR(__n)   (0xD0 + ((__n)*4))
#define GICV2_GICC_NSAPR(__n) (0xE0 + ((__n)*4))
#define GICV2_GICC_IIDR       (0xFC)
#define GICV2_GICC_DIR        (0x1000)

__maybe_unused
static inline uint32_t
gicd_read(
        struct gicv2 *gic,
        size_t reg_offset)
{
    DEBUG_ASSERT(reg_offset < gic->gicd_region_size);
    void __mmio *reg = gic->gicd_region + reg_offset;
    return mmio_readl(reg);
}
__maybe_unused
static inline void
gicd_write(
        struct gicv2 *gic,
        size_t reg_offset,
        uint32_t value)
{
    DEBUG_ASSERT(reg_offset < gic->gicd_region_size);
    void __mmio *reg = gic->gicd_region + reg_offset;
    mmio_writel(reg, value);
}

__maybe_unused
static inline uint32_t
gicc_read(
        struct gicv2_cpu_interface *cpu_int,
        size_t reg_offset)
{
    DEBUG_ASSERT(reg_offset < cpu_int->gicc_region_size);
    void __mmio *reg = cpu_int->gicc_region + reg_offset;
    return mmio_readl(reg);
}
__maybe_unused
static inline void
gicc_write(
        struct gicv2_cpu_interface *cpu_int,
        size_t reg_offset,
        uint32_t value)
{
    DEBUG_ASSERT(reg_offset < cpu_int->gicc_region_size);
    void __mmio *reg = cpu_int->gicc_region + reg_offset;
    mmio_writel(reg, value);
}

// IRQ Device Functions

struct gicv2_irq_xcall_state {
    struct gicv2 *gic;
    hwirq_t hwirq;
};

static inline int
gicv2_set_irq_edge_triggered_local(
        struct gicv2 *gic,
        hwirq_t hwirq)
{
    if(hwirq < 16) {
        return -EINVAL;
    }
    size_t register_index = hwirq / 16;
    size_t register_shift = (hwirq % 16)*2;

    uint32_t reg = gicd_read(gic, GICV2_GICD_ICFGR(register_index));
    reg &= ~(0b11 << register_shift);
    reg |=  (0b10 << register_shift);
    gicd_write(gic, GICV2_GICD_ICFGR(register_index), reg);

    return 0;
}
static inline void
gicv2_set_irq_edge_triggered_xcall(
        void *__state)
{
    struct gicv2_irq_xcall_state *state = __state;
    gicv2_set_irq_edge_triggered_local(state->gic, state->hwirq);
}
static inline int
gicv2_set_irq_edge_triggered_broadcast(
        struct gicv2 *gic,
        hwirq_t hwirq)
{
    int res;
    struct gicv2_irq_xcall_state state = {
        .gic = gic,
        .hwirq = hwirq,
    };
    res = xcall_broadcast(gicv2_set_irq_edge_triggered_xcall, &state);
    if(res) {
        return res;
    }
    return 0;
}
static int
gicv2_set_irq_edge_triggered(struct gicv2 *gic, hwirq_t hwirq)
{
    if(hwirq >= 0 && hwirq < 16) { // SGI
        if((hwirq) >= gic->num_sgi) {
            return -ENXIO;
        }
        return gicv2_set_irq_edge_triggered_local(gic, hwirq);
    }
    else if(hwirq >= 16 && hwirq < 32) { // PPI
        if((hwirq - 16) >= gic->num_ppi) {
            return -ENXIO;
        }
        return gicv2_set_irq_edge_triggered_broadcast(gic, hwirq);
    }
    else if(hwirq >= 32 && hwirq < 1020) { // SPI
        if((hwirq - 32) >= gic->num_spi) {
            return -ENXIO;
        }
        return gicv2_set_irq_edge_triggered_local(gic, hwirq);
    } else {
        return -ENXIO;
    }
    return -EINVAL;
}

static inline int
gicv2_set_irq_level_sensitive_local(
        struct gicv2 *gic,
        hwirq_t hwirq)
{
    if(hwirq < 16) {
        return -EINVAL;
    }
    size_t register_index = hwirq / 16;
    size_t register_shift = (hwirq % 16)*2;

    uint32_t reg = gicd_read(gic, GICV2_GICD_ICFGR(register_index));
    reg &= ~(0b11 << register_shift);
    // reg |=  (0b00 << register_shift);
    gicd_write(gic, GICV2_GICD_ICFGR(register_index), reg);

    return 0;
}
static inline void
gicv2_set_irq_level_sensitive_xcall(
        void *__state)
{
    struct gicv2_irq_xcall_state *state = __state;
    gicv2_set_irq_level_sensitive_local(state->gic, state->hwirq);
}
static inline int
gicv2_set_irq_level_sensitive_broadcast(
        struct gicv2 *gic,
        hwirq_t hwirq)
{
    int res;
    struct gicv2_irq_xcall_state state = {
        .gic = gic,
        .hwirq = hwirq,
    };
    res = xcall_broadcast(gicv2_set_irq_level_sensitive_xcall, &state);
    if(res) {
        return res;
    }
    return 0;
}
static int
gicv2_set_irq_level_sensitive(struct gicv2 *gic, hwirq_t hwirq)
{
    if(hwirq >= 0 && hwirq < 16) { // SGI
        if((hwirq) >= gic->num_sgi) {
            return -ENXIO;
        }
        return gicv2_set_irq_level_sensitive_local(gic, hwirq);
    }
    else if(hwirq >= 16 && hwirq < 32) { // PPI
        if((hwirq - 16) >= gic->num_ppi) {
            return -ENXIO;
        }
        return gicv2_set_irq_level_sensitive_broadcast(gic, hwirq);
    }
    else if(hwirq >= 32 && hwirq < 1020) { // SPI
        if((hwirq - 32) >= gic->num_spi) {
            return -ENXIO;
        }
        return gicv2_set_irq_level_sensitive_local(gic, hwirq);
    } else {
        return -ENXIO;
    }
    return -EINVAL;
}

static inline int
gicv2_mask_irq_local(
        struct gicv2 *gic,
        hwirq_t hwirq)
{
    dprintk("gicv2_mask_irq_local (cpu=%ld, hwirq=%ld)\n",
            (sl_t)current_cpu_id(),
            (sl_t)hwirq);
    size_t register_index = hwirq / 32;
    uint32_t mask = (1UL<<(hwirq % 32));
    gicd_write(gic, GICV2_GICD_ICENABLER(register_index), mask);
    return 0;
}
static inline void
gicv2_mask_irq_xcall(
        void *__state)
{
    struct gicv2_irq_xcall_state *state = __state;
    gicv2_mask_irq_local(state->gic, state->hwirq);
}
static inline int
gicv2_mask_irq_broadcast(
        struct gicv2 *gic,
        hwirq_t hwirq)
{
    int res;
    struct gicv2_irq_xcall_state state = {
        .gic = gic,
        .hwirq = hwirq,
    };
    res = xcall_broadcast(gicv2_mask_irq_xcall, &state);
    if(res) {
        return res;
    }
    return 0;
}
static int
gicv2_mask_irq(struct irq_dev *irq_dev, hwirq_t hwirq)
{
    struct gicv2 *gic = container_of(irq_dev, struct gicv2, irq_dev);
    if(hwirq >= 0 && hwirq < 16) { // SGI
        if((hwirq) >= gic->num_sgi) {
            return -ENXIO;
        }
        return gicv2_mask_irq_local(gic, hwirq);
    }
    else if(hwirq >= 16 && hwirq < 32) { // PPI
        if((hwirq - 16) >= gic->num_ppi) {
            return -ENXIO;
        }
        return gicv2_mask_irq_broadcast(gic, hwirq);
    }
    else if(hwirq >= 32 && hwirq < 1020) { // SPI
        if((hwirq - 32) >= gic->num_spi) {
            return -ENXIO;
        }
        return gicv2_mask_irq_local(gic, hwirq);
    } else {
        return -ENXIO;
    }
    return -EINVAL;
}

static inline int
gicv2_unmask_irq_local(
        struct gicv2 *gic,
        hwirq_t hwirq)
{
    dprintk("gicv2_unmask_irq_local (cpu=%ld, hwirq=%ld)\n",
            (sl_t)current_cpu_id(),
            (sl_t)hwirq);

    size_t register_index = hwirq / 32;
    uint32_t mask = (1UL<<(hwirq % 32));
    gicd_write(gic, GICV2_GICD_ISENABLER(register_index), mask);

    return 0;
}
static inline void
gicv2_unmask_irq_xcall(
        void *__state)
{
    struct gicv2_irq_xcall_state *state = __state;
    gicv2_unmask_irq_local(state->gic, state->hwirq);
}
static inline int
gicv2_unmask_irq_broadcast(
        struct gicv2 *gic,
        hwirq_t hwirq)
{
    int res;
    struct gicv2_irq_xcall_state state = {
        .gic = gic,
        .hwirq = hwirq,
    };
    res = xcall_broadcast(gicv2_unmask_irq_xcall, &state);
    if(res) {
        return res;
    }
    return 0;
}
static int
gicv2_unmask_irq(struct irq_dev *irq_dev, hwirq_t hwirq)
{
    struct gicv2 *gic = container_of(irq_dev, struct gicv2, irq_dev);
    if(hwirq >= 0 && hwirq < 16) { // SGI
        if((hwirq) >= gic->num_sgi) {
            return -ENXIO;
        }
        return gicv2_unmask_irq_local(gic, hwirq);
    }
    else if(hwirq >= 16 && hwirq < 32) { // PPI
        if((hwirq - 16) >= gic->num_ppi) {
            return -ENXIO;
        }
        return gicv2_unmask_irq_broadcast(gic, hwirq);
    }
    else if(hwirq >= 32 && hwirq < 1020) { // SPI
        if((hwirq - 32) >= gic->num_spi) {
            return -ENXIO;
        }
        return gicv2_unmask_irq_local(gic, hwirq);
    } else {
        return -ENXIO;
    }
    return -EINVAL;
}

static int
gicv2_ack_irq(struct irq_dev *irq_dev, hwirq_t hwirq)
{
    // Everything is routed into our IRQ handler
    // which does ACK/EOI
    return 0;
}
static int
gicv2_eoi_irq(struct irq_dev *irq_dev, hwirq_t hwirq)
{
    // Everything is routed into our IRQ handler
    // which does ACK/EOI
    return 0;
}
static unsigned long
gicv2_irq_status(struct irq_dev *irq_dev, hwirq_t hwirq)
{
    struct gicv2 *gic = container_of(irq_dev, struct gicv2, irq_dev);
    return IRQ_STATUS_UNKNOWN;
}
int
gicv2_trigger_irq(struct irq_dev *irq_dev, hwirq_t hwirq)
{
    return -EUNIMPL;
}

static int
gicv2_describe_irq(
        struct irq_dev *irq_dev,
        hwirq_t hwirq,
        char *buffer,
        size_t buflen)
{
    snprintk(buffer, buflen,
            "gicv2-%lu",
            (ul_t)hwirq);
    return 0;
}

static struct irq_driver gicv2_irq_driver = {
    .ack_irq = gicv2_ack_irq,
    .eoi_irq = gicv2_eoi_irq,
    .mask_irq = gicv2_mask_irq,
    .unmask_irq = gicv2_unmask_irq,
    .irq_status = gicv2_irq_status,
    .trigger_irq = gicv2_trigger_irq,
    .describe_irq = gicv2_describe_irq,
};

// Root IRQ Handler
static int
gicv2_handle_irq(
        struct excp_state *excp_state,
        struct irq_action *action)
{
    int res;

    struct gicv2 *gic = action->handler_data.priv_data;
    cpu_id_t cpu_id = current_cpu_id();
    if(cpu_id >= gic->num_cpu_interfaces) {
        return IRQ_UNHANDLED;
    }
    struct gicv2_cpu_interface *inter = &gic->cpu_interfaces[cpu_id];

    uint32_t intid = gicc_read(inter, GICV2_GICC_IAR);
    hwirq_t hwirq = intid & 0x3FF;
    dprintk("GICv2: hwirq=%lu\n", (ul_t)hwirq);
    if(hwirq >= 1020 && hwirq <= 1023) {
        // Spurrious
        return IRQ_NONE;
    }

    irq_t irq = NULL_IRQ;
    if(hwirq < 16) {
        // SGI
        irq = irq_domain_revmap(gic->sgi_domain, hwirq);
    } else if(hwirq < 32) {
        // PPI
        irq = irq_domain_revmap(gic->ppi_domain, hwirq);
    } else if(hwirq < 1020) {
        // SPI
        irq = irq_domain_revmap(gic->spi_domain, hwirq);
    } else {
        wprintk("Invalid GICv2 HWIRQ(%lu)!\n", (ul_t)hwirq);
        return IRQ_UNHANDLED;
    }
    if(irq == NULL_IRQ) {
        wprintk("GICv2 Failed to find IRQ corresponding to HWIRQ(%lu)!\n",
                (ul_t)hwirq);
        return IRQ_UNHANDLED;
    }

    //printk("Routing GICv2 hwirq(%lu)\n", (ul_t)hwirq);
    struct irq_desc *desc = irq_to_desc(irq);
    res = handle_irq(desc, excp_state);
    dprintk("Writing EOI 0x%lx\n", intid);
    gicc_write(inter, GICV2_GICC_EOIR, intid);
//    { // Check that this IRQ is not inactive
//        size_t register_index = hwirq / 32;
//        size_t mask = (1ULL<<(hwirq % 32));
//        uint32_t active = gicd_read(gic, GICV2_GICD_ISACTIVER(register_index));
//        if(active & mask) {
//            wprintk("GICv2 HWIRQ(%lu) is still active after EOI!\n",
//                    (ul_t)hwirq);
//        }
//    }
    return res;
}


// Devtree Functions
static int
gicv2_dt_probe(struct dt_driver *driver, struct dt_node *node)
{
    return 0;
}

static inline void
gicv2_setup_cpu_interface_xcall(void *_gic)
{
    struct gicv2 *gic = _gic;
    cpu_id_t cpu_id = current_cpu_id();
    printk("GICv2: CPU %lu Setting GICC CPU Interface\n",
            (ul_t)cpu_id);
    if(cpu_id >= gic->num_cpu_interfaces) {
        wprintk("gicv2_setup_cpu_interface: CPU %lu is out of range for the GICv2 number of CPU interfaces (#inter=%lu)!\n",
                (ul_t)cpu_id,
                (ul_t)gic->num_cpu_interfaces);
        return;
    }

    struct gicv2_cpu_interface *inter = &gic->cpu_interfaces[cpu_id];

    // Set the "target" of every SGI/PPI (banked per processor)
    {
        for(hwirq_t hwirq = 0; hwirq < gic->num_sgi; hwirq++) {
            uint32_t register_index = hwirq / 4;
            uint32_t register_byte = hwirq % 4;
            uint32_t reg = gicd_read(gic, GICV2_GICD_ITARGETSR(register_index));
            reg |= (0xFFUL<<(register_byte*8));
            gicd_write(gic, GICV2_GICD_ITARGETSR(register_index), reg);
        }
        for(hwirq_t hwirq = 16; hwirq < 16 + gic->num_ppi; hwirq++) {
            uint32_t register_index = hwirq / 4;
            uint32_t register_byte = hwirq % 4;
            uint32_t reg = gicd_read(gic, GICV2_GICD_ITARGETSR(register_index));
            reg |= (0xFFUL<<(register_byte*8)); // Set the target to "all"
            gicd_write(gic, GICV2_GICD_ITARGETSR(register_index), reg);
        }
    }
    
    // Set the "priority" of every SGI/PPI (banked per processor)
    {
        for(hwirq_t hwirq = 0; hwirq < gic->num_sgi; hwirq++) {
            uint32_t register_index = hwirq / 4;
            uint32_t register_byte = hwirq % 4;
            uint32_t reg = gicd_read(gic, GICV2_GICD_IPRIORITYR(register_index));
            reg &= ~(0xFFUL<<(register_byte*8));
            gicd_write(gic, GICV2_GICD_IPRIORITYR(register_index), reg);
        }
        for(hwirq_t hwirq = 16; hwirq < 16 + gic->num_ppi; hwirq++) {
            uint32_t register_index = hwirq / 4;
            uint32_t register_byte = hwirq % 4;
            uint32_t reg = gicd_read(gic, GICV2_GICD_IPRIORITYR(register_index));
            reg &= ~(0xFFUL<<(register_byte*8)); // Clear the bits (0 is highest priority)
            gicd_write(gic, GICV2_GICD_IPRIORITYR(register_index), reg);
        }
    }
 
    // Enable Group 1 Interrupts
    uint32_t ctlr = gicc_read(inter, GICV2_GICC_CTLR);
    ctlr |= 0b1; // Enable IRQ(s)
    ctlr &= ~(1UL<<9); // EOI does priority drop and deactivate
    gicc_write(inter, GICV2_GICC_CTLR, ctlr);

    // Set the processor to the minimum priority
    uint32_t pmr = gicc_read(inter, GICV2_GICC_PMR);
    pmr |= 0xFFUL;
    gicc_write(inter, GICV2_GICC_PMR, pmr);

    return;
}

static int
gicv2_dt_init(struct dt_driver *driver, struct dt_node *node)
{
    int res;
    struct gicv2 *gic = kzmalloc(sizeof(*gic), KM_KERNEL);
    if(gic == NULL) {
        return -ENOMEM;
    }

    {
        void __phys *reg[2];
        size_t reglen[2];
        res = dt_node_read_reg(node, 2, reg, reglen);
        if(res) {
            kfree(gic);
            return res;
        }
        gic->gicd_region_size = reglen[0];
        gic->gicd_region = mmio_map(reg[0], gic->gicd_region_size);
        if(gic->gicd_region == NULL) {
            kfree(gic);
            return -ENOMEM;
        }
        gic->gicc_region_size = reglen[1];
        gic->gicc_region = mmio_map(reg[1], gic->gicc_region_size);
        if(gic->gicc_region == NULL) {
            mmio_unmap(gic->gicd_region, gic->gicd_region_size);
            kfree(gic);
            return -ENOMEM;
        }
        printk("GICv2 GICD=[%p-%p)\n", reg[0], reg[0]+gic->gicd_region_size);
        printk("GICv2 GICC=[%p-%p)\n", reg[1], reg[1]+gic->gicc_region_size);
    }

    // Ensure no interrupts are delivered while we are configuring the GIC
    gicd_write(gic, GICV2_GICD_CTLR, gicd_read(gic, GICV2_GICD_CTLR) & ~0b11);

    {
    uint32_t typer = gicd_read(gic, GICV2_GICD_TYPER);
    uint8_t itlinesnumber = typer & 0x1F;
    uint8_t cpu_number = (typer >> 5) & 0x7;

    size_t max_num_interrupts = 32*(itlinesnumber+1);
    if(max_num_interrupts > 1020) {
        max_num_interrupts = 1020;
    }
    if(max_num_interrupts <= 16) {
        gic->num_sgi = max_num_interrupts;
        gic->num_ppi = 0;
        gic->num_spi = 0;
    } else if(max_num_interrupts <= 32) {
        gic->num_sgi = 16;
        gic->num_ppi = max_num_interrupts - 16;
        gic->num_spi = 0;
    } else {
        gic->num_sgi = 16;
        gic->num_ppi = 16;
        gic->num_spi = max_num_interrupts - 32;
    }
    gic->num_cpu_interfaces = cpu_number+1;
    gic->security_ext = (typer >> 10) & 1;
    }

    // Create the interrupt domain(s)
    gic->sgi_domain = gic->num_sgi > 0 ? alloc_irq_domain_linear(0, gic->num_sgi) : NULL;
    gic->ppi_domain = gic->num_ppi > 0 ? alloc_irq_domain_linear(16, gic->num_ppi) : NULL;
    gic->spi_domain = gic->num_spi > 0 ? alloc_irq_domain_linear(32, gic->num_spi) : NULL;

    if((gic->num_sgi > 0 && gic->sgi_domain == NULL)
    || (gic->num_ppi > 0 && gic->ppi_domain == NULL)
    || (gic->num_spi > 0 && gic->spi_domain == NULL))
    {
        if(gic->sgi_domain) {free_irq_domain_linear(gic->sgi_domain);}
        if(gic->ppi_domain) {free_irq_domain_linear(gic->ppi_domain);}
        if(gic->spi_domain) {free_irq_domain_linear(gic->spi_domain);}
        mmio_unmap(gic->gicc_region, gic->gicc_region_size);
        mmio_unmap(gic->gicd_region, gic->gicd_region_size);
        kfree(gic);
        return -ENOMEM;
    }

    // Create the CPU interfaces
    gic->cpu_interfaces = kzmalloc(sizeof(struct gicv2_cpu_interface) * gic->num_cpu_interfaces, KM_KERNEL);
    if(gic->cpu_interfaces == NULL) {
        return -EINVAL;
    }
    for(size_t i = 0; i < gic->num_cpu_interfaces; i++) {
        struct gicv2_cpu_interface *interface = &gic->cpu_interfaces[i];
        interface->gic = gic;
        interface->gicc_region = gic->gicc_region;
        interface->gicc_region_size = gic->gicc_region_size;
    }

    // Install the IRQ Action
    irq_t root_irq = arm64_exception_irq(ARM64_EXCP_HWIRQ_IRQ);
    if(root_irq == NULL_IRQ) {
        kfree(gic->cpu_interfaces);
        if(gic->sgi_domain) {free_irq_domain_linear(gic->sgi_domain);}
        if(gic->ppi_domain) {free_irq_domain_linear(gic->ppi_domain);}
        if(gic->spi_domain) {free_irq_domain_linear(gic->spi_domain);}
        mmio_unmap(gic->gicc_region, gic->gicc_region_size);
        mmio_unmap(gic->gicd_region, gic->gicd_region_size);
        kfree(gic);
        return -ENXIO;
    }

    gic->root_action = irq_install_handler(
            irq_to_desc(root_irq),
            gic,
            gicv2_handle_irq);
    if(gic->root_action == NULL) {
        kfree(gic->cpu_interfaces);
        if(gic->sgi_domain) {free_irq_domain_linear(gic->sgi_domain);}
        if(gic->ppi_domain) {free_irq_domain_linear(gic->ppi_domain);}
        if(gic->spi_domain) {free_irq_domain_linear(gic->spi_domain);}
        mmio_unmap(gic->gicc_region, gic->gicc_region_size);
        mmio_unmap(gic->gicd_region, gic->gicd_region_size);
        kfree(gic);
        return -ENXIO;
    }

    gic->irq_dev.driver = &gicv2_irq_driver;
    res = register_irq_dev(&gic->irq_dev, "gicv2");
    if(res) {
        irq_uninstall_action(gic->root_action);
        kfree(gic->cpu_interfaces);
        if(gic->sgi_domain) {free_irq_domain_linear(gic->sgi_domain);}
        if(gic->ppi_domain) {free_irq_domain_linear(gic->ppi_domain);}
        if(gic->spi_domain) {free_irq_domain_linear(gic->spi_domain);}
        mmio_unmap(gic->gicc_region, gic->gicc_region_size);
        mmio_unmap(gic->gicd_region, gic->gicd_region_size);
        kfree(gic);
        return -ENOMEM;
    }

    irq_domain_set_all_irq_dev(gic->sgi_domain, &gic->irq_dev);
    irq_domain_set_all_irq_dev(gic->ppi_domain, &gic->irq_dev);
    irq_domain_set_all_irq_dev(gic->spi_domain, &gic->irq_dev);

    node->driver_state = gic;

    // Allow IRQ's to be delivered
    gicd_write(gic, GICV2_GICD_CTLR, gicd_read(gic, GICV2_GICD_CTLR) | 0b11);

    // Queue an xcall on all CPU(s)
    // to configure their GICC registers
    res = xcall_broadcast_queue(gicv2_setup_cpu_interface_xcall, gic);
    if(res) {
        wprintk("Failed to queue GICC setup xcall on all CPU(s)! (err=%e)\n",
                res);
        irq_uninstall_action(gic->root_action);
        unregister_irq_dev(&gic->irq_dev);
        kfree(gic->cpu_interfaces);
        if(gic->sgi_domain) {free_irq_domain_linear(gic->sgi_domain);}
        if(gic->ppi_domain) {free_irq_domain_linear(gic->ppi_domain);}
        if(gic->spi_domain) {free_irq_domain_linear(gic->spi_domain);}
        mmio_unmap(gic->gicc_region, gic->gicc_region_size);
        mmio_unmap(gic->gicd_region, gic->gicd_region_size);
        kfree(gic);
        return res;
    }

    res = xcall_handle_pending();
    DEBUG_ASSERT(res == 0);

    return 0;
}

static int
gicv2_dt_deinit(struct dt_driver *driver, struct dt_node *node)
{
    struct gicv2 *gic = node->driver_state;
    return -EUNIMPL;
}

static irq_t
gicv2_dt_xlate_irq(struct dt_driver *driver,
                         struct dt_node *node,
                         const fdt32_t *cells,
                         size_t cell_count)
{
    struct gicv2 *gic = node->driver_state;
    if(cell_count != 3) {
        return -EINVAL;
    }

    int is_ppi = fdttoh32(cells[0]);
    uint32_t hwirq_offset = fdttoh32(cells[1]);
    uint32_t flags = fdttoh32(cells[2]);

    hwirq_t hwirq;
    irq_t irq;
    if(is_ppi) {
        if(gic->ppi_domain == NULL) {
            return NULL_IRQ;
        }
        hwirq = hwirq_offset + 16;
        irq = irq_domain_revmap(gic->ppi_domain, hwirq);
    } else { // is_spi
        if(gic->spi_domain == NULL) {
            return NULL_IRQ;
        }
        hwirq = hwirq_offset + 32;
        irq = irq_domain_revmap(gic->spi_domain, hwirq); 
    }

    uint8_t trigger_flags = flags & 0xF;
    switch(trigger_flags) {
        case 1: // low-to-high edge triggered
            printk("GICv2 xlate_irq: low-to-high edge triggered\n");
            gicv2_set_irq_edge_triggered(gic, hwirq);
            break;
        case 2: // high-to-low edge triggered
            printk("GICv2 xlate_irq: high-to-low edge triggered\n");
            gicv2_set_irq_edge_triggered(gic, hwirq);
            break;
        case 4: // active high level sensitive
            printk("GICv2 xlate_irq: active high level sensitive\n");
            gicv2_set_irq_level_sensitive(gic, hwirq);
            break;
        case 8: // active low level sensitive
            printk("GICv2 xlate_irq: active low level sensitive\n");
            gicv2_set_irq_level_sensitive(gic, hwirq);
            break;
        default:
            return -EINVAL;
    }

    printk("GIC IRQ XLATE -> %ld\n", (sl_t)irq);
    return irq;
}


struct dt_driver_ops gicv2_dt_driver_ops = {
    .probe = gicv2_dt_probe,
    .init_node = gicv2_dt_init,
    .deinit_node = gicv2_dt_deinit,
    .xlate_irq = gicv2_dt_xlate_irq,
    .xlate_irq_map = dt_driver_xlate_irq_map_ignore_address,
};

struct dt_node_id gicv2_dt_ids[] = {
    {.compatible = "sifive,plic-1.0.0"},
    {.compatible = "arm,arm1176jzf-devchip-gic"},
    {.compatible = "arm,arm11mp-gic"},
    {.compatible = "arm,cortex-a15-gic"},
    {.compatible = "arm,cortex-a7-gic"},
    {.compatible = "arm,cortex-a9-gic"},
    {.compatible = "arm,eb11mp-gic"},
    {.compatible = "arm,gic-400"},
    {.compatible = "arm,pl390"},
    {.compatible = "arm,tc11mp-gic"},
    {.compatible = "brcm,brahma-b15-gic"},
    {.compatible = "nvidia,tegra210-agic"},
    {.compatible = "qcom,msm-8660-qgic"},
    {.compatible = "qcom,msm-qgic2"},
};

struct dt_driver gicv2_dt_driver = {
    .num_ids = sizeof(gicv2_dt_ids) / sizeof(struct dt_node_id),
    .ids = gicv2_dt_ids,
    .ops = &gicv2_dt_driver_ops,
};

static int
register_gicv2_driver(void)
{
    int res;
    res = register_dt_driver(&gicv2_dt_driver);
    if(res)
    {
        return res;
    }
    return 0;
}
declare_init_desc(xcall,
                  register_gicv2_driver,
                  "Registering GICv2 Driver");
