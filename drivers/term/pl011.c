
#include <kanawha/types.h>
#include <kanawha/pointer.h>
#include <kanawha/vmem.h>
#include <kanawha/mmio.h>
#include <kanawha/init.h>
#include <kanawha/ptree.h>
#include <kanawha/lock.h>
#include <kanawha/irq_domain.h>
#include <kanawha/dev/term.h>
#include <kanawha/kmalloc.h>
#include <devtree/devtree.h>
#include <devtree/driver.h>

#ifdef CONFIG_PL011_SERIAL_AT_BOOT
static int pl011_boot_printk_handler(char c);
#endif

#define PL011_REG_DR    (0x000)
#define PL011_REG_RSR   (0x004)
#define PL011_REG_ECR   (0x004)
#define PL011_REG_FR    (0x018)
#define PL011_REG_ILPR  (0x020)
#define PL011_REG_IBRD  (0x024)
#define PL011_REG_FBRD  (0x028)
#define PL011_REG_LCR_H (0x02C)
#define PL011_REG_CR    (0x030)
#define PL011_REG_IFLS  (0x034)
#define PL011_REG_IMSC  (0x038)
#define PL011_REG_RIS   (0x03C)
#define PL011_REG_MIS   (0x040)
#define PL011_REG_ICR   (0x044)
#define PL011_REG_DMACR (0x048)
#define PL011_REG_PeriphID0 (0xFE0)
#define PL011_REG_PeriphID1 (0xFE4)
#define PL011_REG_PeriphID2 (0xFE8)
#define PL011_REG_PeriphID3 (0xFEC)
#define PL011_REG_PCellID0  (0xFF0)
#define PL011_REG_PCellID1  (0xFF4)
#define PL011_REG_PCellID2  (0xFF8)
#define PL011_REG_PCellID3  (0xFFC)

static DECLARE_PTREE(pl011_tree);
DEFINE_LOCAL_IRQ_LOCK(pl011_tree_lock);

#define PL011_NAMEBUFLEN 16
#define PL011_DEFAULT_BAUD 115200
#define PL011_DEFAULT_FREQ_HZ 24000000

struct pl011 {
    size_t regsize;
    void __mmio *regbase;

    char namebuf[PL011_NAMEBUFLEN];
    struct ptree_node ptree_node;

    freq_t clock_freq;
    baud_t baudrate;

    irq_t irq;
    struct irq_action *action;

    struct term_dev term_dev;
};

static inline uint32_t
pl011_read_reg(struct pl011 *p, size_t offset)
{
    le32_t le_reg = mmio_readl(p->regbase + offset);
    return letoh32(le_reg);
}
static inline int
pl011_write_reg(struct pl011 *p, size_t offset, uint32_t value)
{
    le32_t le_value = htole32(value);
    mmio_writel(p->regbase + offset, le_value);
    return 0;
}

static inline int
pl011_busy(struct pl011 *p)
{
    uint32_t flags = pl011_read_reg(p, PL011_REG_FR);
    if(flags & (1<<3)) {
        return 1;
    } else {
        return 0;
    }
}

static inline int
pl011_xmit_empty(struct pl011 *p)
{
    uint32_t flags = pl011_read_reg(p, PL011_REG_FR);
    if(flags & (1<<7)) {
        return 1;
    } else {
        return 0;
    }
}
static inline int
pl011_xmit_full(struct pl011 *p)
{
    uint32_t flags = pl011_read_reg(p, PL011_REG_FR);
    if(flags & (1<<5)) {
        return 1;
    } else {
        return 0;
    }
}
static inline int
pl011_recv_empty(struct pl011 *p)
{
    uint32_t flags = pl011_read_reg(p, PL011_REG_FR);
    if(flags & (1<<4)) {
        return 1;
    } else {
        return 0;
    }
}
__maybe_unused
static inline int
pl011_recv_full(struct pl011 *p)
{
    uint32_t flags = pl011_read_reg(p, PL011_REG_FR);
    if(flags & (1<<6)) {
        return 1;
    } else {
        return 0;
    }
}

static inline int
pl011_disable(struct pl011 *p)
{
    uint32_t ctlr = pl011_read_reg(p, PL011_REG_CR);
    ctlr &= ~(1UL<<0);
    pl011_write_reg(p, PL011_REG_CR, ctlr);

    duration_t start = clk_mono_current();
    duration_t timeout = start + sec_to_duration(1);
    while(pl011_busy(p)) {
        duration_t now = clk_mono_current();
        if(now > timeout) {
            return -ETIMEDOUT;
        }
        clk_delay(msec_to_duration(1));
    }

    return 0;
}

static inline int
pl011_enable(struct pl011 *p)
{
    uint32_t ctlr = pl011_read_reg(p, PL011_REG_CR);
    ctlr |= (1UL<<0);
    pl011_write_reg(p, PL011_REG_CR, ctlr);
    return 0;
}

static int
pl011_term_dev_putc(
        struct term_dev *term_dev,
        char c)
{
    struct pl011 *p = container_of(term_dev, struct pl011, term_dev);
    while(pl011_busy(p) || pl011_xmit_full(p)) {
        // TODO: Yield?
    }
    pl011_write_reg(p, PL011_REG_DR, htole32((uint32_t)c));
    return 0;
}

static int
pl011_term_dev_flush(
        struct term_dev *term_dev)
{
    struct pl011 *p = container_of(term_dev, struct pl011, term_dev);
    while(pl011_busy(p) || !pl011_xmit_empty(p)) {
        // TODO: Yield?
    }
    return 0;
}

int
pl011_term_dev_get_baudrate(
        struct term_dev *term_dev,
        baud_t *baud_out)
{
    struct pl011 *p = container_of(term_dev, struct pl011, term_dev);
    if(baud_out) {
        *baud_out = p->baudrate;
    }
    return 0;
}
int
pl011_term_dev_set_baudrate(
        struct term_dev *term_dev,
        baud_t baud)
{
    struct pl011 *p = container_of(term_dev, struct pl011, term_dev);
    if(baud == p->baudrate) {
        return 0;
    }
    // TODO
    return -EUNIMPL;
}

static struct term_driver
pl011_term_driver = {
    .putc = pl011_term_dev_putc,
    .flush = pl011_term_dev_flush,
    .get_baudrate = pl011_term_dev_get_baudrate,
    .set_baudrate = pl011_term_dev_set_baudrate,
};

static int
pl011_term_dev_irq_handler(
        struct excp_state *excp_state,
        struct irq_action *action)
{
    // printk("pl011_term_dev_irq_handler!\n");
    struct pl011 *term = action->handler_data.priv_data;
    while(pl011_busy(term)) {
        // Waiting... Hmmmm Maybe we shouldn't be waiting
        // in an IRQ handler... -KJH TODO
    }
    uint32_t irq_status = pl011_read_reg(term, PL011_REG_MIS);
    if(!pl011_recv_empty(term)) {
        // We should read some byte
        uint32_t dr = pl011_read_reg(term, PL011_REG_DR);
        char c = (char)dr;
        term_driver_provide_input(&term->term_dev, c);
    }
    pl011_write_reg(term, PL011_REG_ICR, irq_status);
    return IRQ_NONE;
}

struct pl011 *printk_pl011 = NULL;
static int
pl011_printk_handler(char c)
{
    uint32_t value = c;
    if(printk_pl011 == NULL) {
        return 0;
    }
    return pl011_term_dev_putc(&printk_pl011->term_dev, c);
}

static struct pl011 *
pl011_create(void __phys *reg_phys,
             size_t reg_size,
             freq_t clock_freq,
             irq_t irq)
{
    int res;
    int setup_printk = 0;

#ifdef CONFIG_PL011_SERIAL_AT_BOOT
    if(reg_phys == (void __phys *)CONFIG_PL011_SERIAL_AT_BOOT_ADDR) {
        setup_printk = 1;
        printk("Removing PL011 Boot printk Handler\n");
        printk_remove_handler(pl011_boot_printk_handler);
    }
#endif

    struct pl011 *term = kzmalloc(sizeof(*term), KM_KERNEL);
    if(term == NULL) {
        return NULL;
    }
    term->regsize = reg_size;
    term->regbase = mmio_map(reg_phys, reg_size);
    term->clock_freq = clock_freq;
    if(term->regbase == NULL) {
        kfree(term);
        return NULL;
    }

    res = pl011_disable(term);
    if(res) {
        mmio_unmap(term->regbase, term->regsize);
        kfree(term);
        return NULL;
    }

    term->irq = irq;
    term->action = irq_install_handler(
            irq_to_desc(term->irq),
            term,
            pl011_term_dev_irq_handler);
    if(term->action == NULL) {
        mmio_unmap(term->regbase, term->regsize);
        kfree(term);
        return NULL;
    }

    pl011_tree_lock_acquire();
    res = ptree_insert_any(&pl011_tree, &term->ptree_node);
    pl011_tree_lock_release();
    if(res) {
        irq_uninstall_action(term->action);
        mmio_unmap(term->regbase, term->regsize);
        kfree(term);
        return NULL;
    }
    snprintk(term->namebuf, PL011_NAMEBUFLEN,
             "pl011-%lu", (ul_t)term->ptree_node.key);
    term->namebuf[PL011_NAMEBUFLEN-1] = '\0';

    // Configure the PL011
    term->baudrate = PL011_DEFAULT_BAUD;
    uint64_t hz = freq_to_hz(term->clock_freq);
    uint32_t div_mult = ((1<<6)*(hz)) / term->baudrate;
    uint16_t div_int = (div_mult>>6) & 0xFFFF;
    uint16_t div_frac = div_mult & 0x3F;
    pl011_write_reg(term, PL011_REG_IBRD, div_int);
    pl011_write_reg(term, PL011_REG_FBRD, div_frac);

    uint32_t line_ctrl_h = pl011_read_reg(term, PL011_REG_LCR_H);
    line_ctrl_h |= (0b11 << 5); // Word Length = 8-bits
    line_ctrl_h &= ~(1<<1); // Disable Parity Checking
    line_ctrl_h &= ~(1<<3); // Single Stop Bit
    line_ctrl_h &= ~(1<<4); // Disable FIFO(s)
    pl011_write_reg(term, PL011_REG_LCR_H, line_ctrl_h);

    uint32_t dma_ctrl = pl011_read_reg(term, PL011_REG_DMACR);
    dma_ctrl = 0; // Disable DMA
    pl011_write_reg(term, PL011_REG_DMACR, dma_ctrl);

    uint32_t ctrl = pl011_read_reg(term, PL011_REG_CR);
    ctrl &= ~(1UL<<1); // Disable SIR
    ctrl |= (1UL<<8); // Enable Transmitting
    ctrl |= (1UL<<9); // Enable Receiving
    pl011_write_reg(term, PL011_REG_CR, ctrl);

    uint32_t int_mask; // = pl011_read_reg(term, PL011_REG_IMSC);
    // The definition of this field in the official PL011 documentation
    // really indicates to me that this is reversed (0 -> interrupt can be raised, 1 -> masked)
    int_mask = 0x0; // Mask all initially
    int_mask |= (1UL<<4); // Unmask recv interrupts
    int_mask |= (1UL<<6); // Unmask recv timeout interrupts
    pl011_write_reg(term, PL011_REG_IMSC, int_mask);

    pl011_enable(term);

    term->term_dev.driver = &pl011_term_driver;
    res = register_term_dev(&term->term_dev, term->namebuf);
    if(res) {
        pl011_disable(term);
        irq_uninstall_action(term->action);
        mmio_unmap(term->regbase, term->regsize);
        kfree(term);
        return NULL;
    }

    unmask_irq(term->irq);

    if(setup_printk) {
        printk_pl011 = term;
        printk_add_handler(pl011_printk_handler);
        printk("Installed PL011 Driver printk Handler\n");
    }

    return term;
}
static int
pl011_destroy(struct pl011 *term)
{
    int res;
    mask_irq(term->irq);
    pl011_disable(term);
    res = unregister_term_dev(&term->term_dev);
    if(res) {
        return res;
    }
    mmio_unmap(term->regbase, term->regsize);
    kfree(term);
    return 0;
}

static int
pl011_dt_probe(struct dt_driver *driver, struct dt_node *node)
{
    return 0;
}

static int
pl011_dt_init(struct dt_driver *driver, struct dt_node *node)
{
    int res;

    void __phys *reg_phys;
    size_t reg_size;
    res = dt_node_read_reg(
            node,
            1,
            &reg_phys,
            &reg_size);
    if(res) {
        return res;
    }

    irq_t irq;
    res = dt_node_read_irq(node, 0, &irq);
    if(res) {
        wprintk("PL011 Failed to get IRQ from device tree! (err=%e)\n",
                res);
        return res;
    }

    freq_t freq = hz_to_freq(PL011_DEFAULT_FREQ_HZ);

    struct pl011 *term;
    term = pl011_create(reg_phys, reg_size, freq, irq);

    node->driver_state = term;

    return 0;
}

static int
pl011_dt_deinit(struct dt_driver *driver, struct dt_node *node)
{
    int res;
    struct pl011 *term = node->driver_state;
    res = pl011_destroy(term);
    if(res) {
        return res;
    }
    node->driver_state = NULL;
    return 0;
}

struct dt_driver_ops pl011_dt_driver_ops = {
    .probe = pl011_dt_probe,
    .init_node = pl011_dt_init,
    .deinit_node = pl011_dt_deinit,
    .xlate_irq = dt_driver_cannot_xlate_irq,
    .xlate_irq_map = dt_driver_cannot_xlate_irq_map,
};

struct dt_node_id pl011_dt_ids[] = {
    {.compatible = "arm,pl011",},
};

struct dt_driver pl011_dt_driver = {
    .num_ids = sizeof(pl011_dt_ids) / sizeof(struct dt_node_id),
    .ids = pl011_dt_ids,
    .ops = &pl011_dt_driver_ops,
};

static int
register_pl011_dt_driver(void)
{
    int res;
    res = register_dt_driver(&pl011_dt_driver);
    if(res)
    {
        return res;
    }
    return 0;
}
declare_init_desc(device,
                  register_pl011_dt_driver,
                  "Registering PL011 Serial Driver");

#ifdef CONFIG_PL011_SERIAL_AT_BOOT

#define pl011_boot_regbase() \
    ((volatile uint8_t *)(__va((void __phys *)(uintptr_t)CONFIG_PL011_SERIAL_AT_BOOT_ADDR)))

#define pl011_boot_read(__offset) \
    (*(volatile uint32_t*)(pl011_boot_regbase() + (__offset)))

#define pl011_boot_write(__offset, __value) \
    do {\
        (*(volatile uint32_t*)(pl011_boot_regbase() + (__offset))) = (__value); \
    } while(0)

static int
pl011_boot_printk_handler(char c)
{
    uint32_t value = c;
    pl011_boot_write(PL011_REG_DR, value);
    return 0;
}

static int
pl011_boot_init(void)
{
    int res;

    { // Turn on the UART
        uint32_t cr = pl011_boot_read(PL011_REG_CR);
        cr |= 0b1; // UARTEN
        pl011_boot_write(PL011_REG_CR, cr);
    }

    res = printk_add_handler(pl011_boot_printk_handler);
    if(res)
    {
        return res;
    }

    return 0;
}
declare_init_desc(boot, pl011_boot_init, "Registering Boot PL011 Serial");

#endif

