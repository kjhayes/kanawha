
#include <drivers/pci/pci.h>
#include <kanawha/dev/blk.h>
#include <kanawha/init.h>

struct ahci
{
    struct pci_func *func;
};

struct ahci_port
{
    struct blk_dev blk_dev;
};

// Register Definitions
#define AHCI_GHC_REG_XLIST(X)                                                  \
    X(HostCap, 0x00)                                                           \
    X(GlobalHostCtrl, 0x04)                                                    \
    X(IRQStatus, 0x08)                                                         \
    X(PortImpl, 0x0C)                                                          \
    X(Version, 0x10)                                                           \
    X(CmdCompletionCoalescingCtrl, 0x14)                                       \
    X(CmdCompletionCoalescingPorts, 0x18)                                      \
    X(EnclosureManagementLoc, 0x1C)                                            \
    X(EnclosureManagementCtrl, 0x20)                                           \
    X(HostCapExt, 0x24)                                                        \
    X(BIOSHandoff, 0x28)

#define AHCI_GHC_DECLARE_OFFSETS(__NAME, __OFFSET, ...)                        \
    const static uint32_t AHCI_GHC_OFFSET_##__NAME = __OFFSET;
AHCI_GHC_REG_XLIST(AHCI_GHC_DECLARE_OFFSETS);
#undef AHCI_GHC_DECLARE_OFFSETS
#undef AHCI_GHC_REG_XLIST

#define ahci_read_ghc(ahci_ptr, __REG)                                         \
    ({                                                                         \
        le32_t le;                                                             \
        le = pci_bar_readl(&(ahci_ptr)->func.bars[5],                          \
                           0x0 + AHCI_GHC_OFFSET_##__REG) letoh32(le);         \
    })

#define ahci_write_ghc(ahci_ptr, __REG, __VAL)                                 \
    ({                                                                         \
        le32_t le = hotle32(__VAL);                                            \
        pci_bar_writel(&(ahci_ptr)->func.bars[5],                              \
                       0x0 + AHCI_GHC_OFFSET_##__REG,                          \
                       le)                                                     \
    })

static int
ahci_probe(struct pci_driver *driver, struct pci_func *func)
{
    int res;

    if(func->bars[5].type != PCI_BAR_MMIO)
    {
        wprintk("AHCI ABAR is not a memory BAR!\n");
        return -EINVAL;
    }

    if(func->bars[5].size < 0x180)
    {
        wprintk("AHCI ABAR is too small to be valid!\n");
        return -EINVAL;
    }

    return -EUNIMPL;
}

static int
ahci_init_device(struct pci_driver *driver, struct pci_func *func)
{
    int res;
    printk("AHCI: init\n");
    struct ahci *ahci = kzmalloc(sizeof(*ahci), KM_KERNEL);
    if(ahci == NULL)
    {
        return -ENOMEM;
    }

    ahci->func = func;
    func->driver_priv_state = ahci;

    return 0;
}

static int
ahci_deinit_device(struct pci_driver *driver, struct pci_func *func)
{
    printk("AHCI: deinit\n");

    struct ahci *ahci = func->driver_priv_state;
    kfree(ahci);

    return 0;
}

static struct pci_id ahci_pci_ids[] = {
    {
        .class = 0x1,
        .subclass = 0x6,
        .flags = PCI_ID_CHECK_CLASS | PCI_ID_CHECK_SUBCLASS |
                 PCI_ID_IGNORE_DEVICE | PCI_ID_IGNORE_VENDOR,
    },
};

static struct pci_driver_ops ahci_pci_driver_ops = {
    .probe = &ahci_probe,
    .init_device = &ahci_init_device,
    .deinit_device = &ahci_deinit_device,
};

static struct pci_driver ahci_pci_driver = {
    .ops = &ahci_pci_driver_ops,
    .num_ids = sizeof(ahci_pci_ids) / sizeof(struct pci_id),
    .ids = ahci_pci_ids,
};

DECLARE_PCI_DRIVER(ahci_pci_driver);
