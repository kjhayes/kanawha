
#include <drivers/pci/bar.h>
#include <drivers/pci/irq.h>
#include <drivers/pci/pci.h>
#include <kanawha/init.h>

__maybe_unused static int
qemu_serial_irq_handler(struct excp_state *excp_state,
                        struct irq_action *action)
{
    struct pci_bar *bar = (struct pci_bar *)action->handler_data.priv_data;
    uint32_t status = pci_bar_readl(bar, 0x24);

    printk("QEMU Serial: IRQ Handler (status=0x%x)\n", status);

    // Acknowledge the interrupt
    pci_bar_writel(bar, 0x64, status);

    return IRQ_NONE;
}

static int
qemu_serial_probe(struct pci_driver *driver, struct pci_func *func)
{
    int res;

    printk("QEMU Serial: probe\n");

    struct pci_bar *bar = &func->bars[0];
    if(bar->type == PCI_BAR_NONE)
    {
        return -EINVAL;
    }

    return -EUNIMPL;
}

static int
qemu_serial_init_device(struct pci_driver *driver, struct pci_func *func)
{
    int res;
    printk("QEMU Serial: init\n");
    return -EUNIMPL;
}

static int
qemu_serial_deinit_device(struct pci_driver *driver, struct pci_func *dev)
{
    printk("QEMU PCI Serial: deinit\n");
    return -EUNIMPL;
}

static struct pci_id qemu_serial_pci_ids[] = {
    {
        // Single Port
        .vendor = 0x1b36,
        .device = 0x0002,
    },
    {
        // Dual Port
        .vendor = 0x1b36,
        .device = 0x0003,
    },
    {
        // Quad Port
        .vendor = 0x1b36,
        .device = 0x0004,
    },
};

static struct pci_driver_ops qemu_serial_pci_driver_ops = {
    .probe = &qemu_serial_probe,
    .init_device = &qemu_serial_init_device,
    .deinit_device = &qemu_serial_deinit_device,
};

static struct pci_driver qemu_serial_pci_driver = {
    .ops = &qemu_serial_pci_driver_ops,
    .num_ids = sizeof(qemu_serial_pci_ids) / sizeof(struct pci_id),
    .ids = qemu_serial_pci_ids,
};

static int
qemu_serial_pci_register(void)
{
    return register_pci_driver(&qemu_serial_pci_driver);
}
declare_init(device, qemu_serial_pci_register);
