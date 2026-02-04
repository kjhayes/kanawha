
#include <drivers/vga/vga.h>
#include <drivers/pci/pci.h>
#include <kanawha/kmalloc.h>


struct vga_pci_dev {
    struct pci_func *pci_func;
    struct vga_dev vga_dev;

    char *name;
};

static int
vga_pci_probe(
        struct pci_driver *driver,
        struct pci_func *func)
{
    dprintk("vga_pci_probe!\n");
    return 0;
}

static int
vga_pci_init_device(
        struct pci_driver *driver,
        struct pci_func *func)
{
    int res;

    struct vga_pci_dev *vga_pci_dev = kmalloc(sizeof(*vga_pci_dev), KM_KERNEL);
    if(vga_pci_dev == NULL) {
        return -ENOMEM;
    }

    func->driver_priv_state = vga_pci_dev;
    vga_pci_dev->pci_func = func;

    {
#define BUFLEN 64
        char buffer[BUFLEN];
        snprintk(buffer, BUFLEN, "%u.%u.%u.%u",
            (u_t)func->segment->segment_id,
            (u_t)func->device->bus->bus_index,
            (u_t)func->device->index,
            (u_t)func->index);
        buffer[BUFLEN-1] = '\0';

        vga_pci_dev->name = kstrdup(buffer);
        if(vga_pci_dev->name == NULL) {
            kfree(vga_pci_dev);
            return -ENOMEM;
        }
#undef BUFLEN
    }

    res = register_vga_dev(&vga_pci_dev->vga_dev, vga_pci_dev->name);
    if(res) {
        kfree(vga_pci_dev->name);
        kfree(vga_pci_dev);
        return res;
    }

    return 0;
}

static int
vga_pci_deinit_device(
        struct pci_driver *driver,
        struct pci_func *func)
{
    int res;
    struct vga_pci_dev *dev = func->driver_priv_state;
    res = unregister_vga_dev(&dev->vga_dev);
    if(res) {
        return res;
    }
    kfree(dev->name);
    kfree(dev);
    func->driver_priv_state = NULL;
    return 0;
}

static struct pci_id
vga_pci_ids[] = {
    {
        .class = 3,
        .subclass = 0,
        .prog_if = 0,
        .flags = PCI_ID_CHECK_CLASS
               | PCI_ID_CHECK_SUBCLASS
               | PCI_ID_CHECK_PROG_IF
               | PCI_ID_IGNORE_VENDOR
               | PCI_ID_IGNORE_DEVICE,
    },
};

static struct pci_driver_ops
vga_pci_driver_ops = {
    .probe = &vga_pci_probe,
    .init_device = &vga_pci_init_device,
    .deinit_device = &vga_pci_deinit_device,
};

static struct pci_driver
vga_pci_driver = {
    .ops = &vga_pci_driver_ops,
    .num_ids = sizeof(vga_pci_ids) / sizeof(struct pci_id),
    .ids = vga_pci_ids,
};

static int
vga_pci_register(void)
{
    return register_pci_driver(&vga_pci_driver);
}
declare_init_desc(device, vga_pci_register, "Registering VGA PCI Driver");

