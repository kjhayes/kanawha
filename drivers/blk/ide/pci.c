
#include <kanawha/init.h>
#include <kanawha/dev/blk.h>
#include <drivers/pci/pci.h>

static int
ide_pci_probe(
        struct pci_driver *driver,
        struct pci_func *func)
{
    return 0;
}

static int
ide_pci_init_device(
        struct pci_driver *driver,
        struct pci_func *func)
{
    int res;
    printk("IDE: init\n");
    return -EUNIMPL;
}

static int
ide_pci_deinit_device(
        struct pci_driver *driver,
        struct pci_func *dev)
{
    printk("IDE: deinit\n");
    return -EUNIMPL;
}

static struct pci_id
ide_pci_ids[] = {
    {
    .class = 0x1,
    .subclass = 0x1,
    .flags = PCI_ID_CHECK_CLASS
	    |PCI_ID_CHECK_SUBCLASS
	    |PCI_ID_IGNORE_DEVICE
	    |PCI_ID_IGNORE_VENDOR,
    },
};

static struct pci_driver_ops
ide_pci_driver_ops = {
    .probe = &ide_pci_probe,
    .init_device = &ide_pci_init_device,
    .deinit_device = &ide_pci_deinit_device,
};

static struct pci_driver 
ide_pci_driver = {
    .ops = &ide_pci_driver_ops,
    .num_ids = sizeof(ide_pci_ids) / sizeof(struct pci_id),
    .ids = ide_pci_ids,
};

static int
ide_pci_register(void)
{
    return register_pci_driver(&ide_pci_driver);
}
declare_init(device, ide_pci_register);

