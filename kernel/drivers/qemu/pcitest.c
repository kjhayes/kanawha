
#include <kanawha/init.h>
#include <drivers/pci/pci.h>

struct pci_test_dev_hdr {
    uint8_t test;        /* write-only, starts a given test number */
    uint8_t width_type;  /*
                          * read-only, type and width of access for a given test.
                          * 1,2,4 for byte,word or long write.
                          * any other value if test not supported on this BAR
                          */
    uint8_t pad0[2];
    uint32_t offset;     /* read-only, offset in this BAR for a given test */
    uint32_t data;       /* read-only, data to use for a given test */
    uint32_t count;      /* for debugging. number of writes detected. */
    uint8_t name[];      /* for debugging. 0-terminated ASCII string. */
};

static int
qemu_test_probe(
        struct pci_driver *driver,
        struct pci_func *dev)
{
    printk("QEMU PCI Test: probe\n");
    return 0;
}

static int
qemu_test_init_device(
        struct pci_driver *driver,
        struct pci_func *dev)
{
    printk("QEMU PCI Test: init\n");

    for(int test = 0; test < 16; test++) {
#define NAME_BUFLEN 0x100
        char name_buf[0x100];

        pci_bar_writeb(&dev->bars[0], offsetof(struct pci_test_dev_hdr, test), test);

        for(size_t i = 0; i < NAME_BUFLEN; i++) {
            name_buf[i] = pci_bar_readb(&dev->bars[0], offsetof(struct pci_test_dev_hdr, name) + i);
            if(name_buf[i] == '\0') {
                break;
            }
        }
        name_buf[NAME_BUFLEN-1] = '\0';
#undef NAME_BUFLEN

        printk("TEST[%d]: \"%s\"\n", test, name_buf);
    }

    panic("Oi");

    return 0;
}

static int
qemu_test_deinit_device(
        struct pci_driver *driver,
        struct pci_func *dev)
{
    printk("QEMU PCI Test: deinit\n");
    return 0;
}

static struct pci_id
qemu_test_pci_ids[] = {
    {
        .vendor = 0x1b36,
        .device = 0x0005,
    },
};

static struct pci_driver_ops
qemu_test_pci_driver_ops = {
    .probe = &qemu_test_probe,
    .init_device = &qemu_test_init_device,
    .deinit_device = &qemu_test_deinit_device,
};

static struct pci_driver 
qemu_test_pci_driver = {
    .ops = &qemu_test_pci_driver_ops,
    .num_ids = sizeof(qemu_test_pci_ids) / sizeof(struct pci_id),
    .ids = qemu_test_pci_ids,
};

static int
qemu_test_pci_register(void)
{
    return register_pci_driver(&qemu_test_pci_driver);
}
declare_init(device, qemu_test_pci_register);

