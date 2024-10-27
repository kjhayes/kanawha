
#include <kanawha/init.h>
#include <drivers/pci/pci.h>
#include <drivers/pci/irq.h>

#define QEMU_EDU_ID         0x00ed

#define QEMU_EDU_ID_REG     0x00
#define QEMU_EDU_INV_REG    0x04
#define QEMU_EDU_FAC_REG    0x08
#define QEMU_EDU_STATUS_REG 0x20

static int
qemu_edu_probe(
        struct pci_driver *driver,
        struct pci_func *dev)
{
    printk("QEMU EDU: probe\n");

    struct pci_bar *bar = &dev->bars[0];

    uint32_t id = pci_bar_readl(bar, QEMU_EDU_ID_REG);
    printk("QEMU EDU Device: ID=0x%x\n",id);
    if((id & 0xFFFF) != QEMU_EDU_ID) {
        return -EINVAL;
    }

    printk("QEMU EDU Device: num_irqs=0x%x, max_irqs=0x%x\n",
            pci_func_num_irqs(dev),
            pci_func_max_num_irqs(dev));

    return 0;
}

static int
qemu_edu_init_device(
        struct pci_driver *driver,
        struct pci_func *dev)
{
    printk("QEMU EDU: init\n");

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

