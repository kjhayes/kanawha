
#include <kanawha/init.h>
#include <drivers/pci/pci.h>
#include <drivers/pci/bar.h>
#include <drivers/pci/irq.h>

#define QEMU_EDU_ID         0x00ed

#define QEMU_EDU_ID_REG     0x00
#define QEMU_EDU_INV_REG    0x04
#define QEMU_EDU_FAC_REG    0x08
#define QEMU_EDU_STATUS_REG 0x20

static int
qemu_edu_irq_handler(
        struct excp_state *excp_state,
        struct irq_action *action)
{
    struct pci_bar *bar = (struct pci_bar *)action->handler_data.priv_data;
    uint32_t status = pci_bar_readl(bar, 0x24);

    printk("QEMU EDU: IRQ Handler (status=0x%x)\n", status);

    // Acknowledge the interrupt
    pci_bar_writel(bar, 0x64, status);

    return IRQ_NONE;
}

static int
qemu_edu_probe(
        struct pci_driver *driver,
        struct pci_func *func)
{
    int res;

    printk("QEMU EDU: probe\n");

    struct pci_bar *bar = &func->bars[0];
    if(bar->type == PCI_BAR_NONE) {
        return -EINVAL;
    }

    uint32_t id = pci_bar_readl(bar, QEMU_EDU_ID_REG);
    printk("QEMU EDU Device: ID=0x%x\n",id);
    if((id & 0xFFFF) != QEMU_EDU_ID) {
        return -EINVAL;
    }

    return 0;
}

static int
qemu_edu_init_device(
        struct pci_driver *driver,
        struct pci_func *func)
{
    int res;

    printk("QEMU EDU: init\n");

    pci_func_raw_enable_pio(func);

    res = pci_func_start_irqs(func);
    if(res) {
        eprintk("Failed to start IRQ's on QEMU EDU device! (err=%s)\n",
                errnostr(res));
        return res;
    }

    irq_t irq = pci_func_get_irq(func, 0);
    if(irq == NULL_IRQ) {
        eprintk("Failed to get QEMU EDU device IRQ 0!\n");
        return -EINVAL;
    }

    printk("QEMU EDU IRQ: 0x%x\n", irq);

    struct pci_bar *bar = &func->bars[0];

    struct irq_action *action = irq_install_handler(
            irq_to_desc(irq),
            NULL,
            (void*)bar,
            qemu_edu_irq_handler);
    if(action == NULL) {
        eprintk("Failed to install QEMU EDU IRQ handler!\n");
        return -EINVAL;
    }

    res = unmask_irq(irq);
    if(res) {
        eprintk("Failed to unmask QEMU EDU IRQ!\n");
        return res;
    }

    // Raise an interrupt
    pci_bar_writel(
            bar,
            0x60,
            0x5);

    return 0;
}

static int
qemu_edu_deinit_device(
        struct pci_driver *driver,
        struct pci_func *dev)
{
    printk("QEMU PCI EDU: deinit\n");
    return 0;
}

static struct pci_id
qemu_edu_pci_ids[] = {
    {
        .vendor = 0x1234,
        .device = 0x11e8,
    },
};

static struct pci_driver_ops
qemu_edu_pci_driver_ops = {
    .probe = &qemu_edu_probe,
    .init_device = &qemu_edu_init_device,
    .deinit_device = &qemu_edu_deinit_device,
};

static struct pci_driver 
qemu_edu_pci_driver = {
    .ops = &qemu_edu_pci_driver_ops,
    .num_ids = sizeof(qemu_edu_pci_ids) / sizeof(struct pci_id),
    .ids = qemu_edu_pci_ids,
};

static int
qemu_edu_pci_register(void)
{
    return register_pci_driver(&qemu_edu_pci_driver);
}
declare_init(device, qemu_edu_pci_register);

