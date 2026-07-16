
#include <drivers/blk/ide/ide.h>
#include <drivers/pci/cfg.h>
#include <drivers/pci/pci.h>
#include <kanawha/dev/blk.h>
#include <kanawha/init.h>

#define PCI_IDE_DEV_NAMEBUFLEN (32)

struct pci_ide_dev
{
    struct ide_dev *primary;
    struct ide_dev *secondary;

    char primary_namebuf[PCI_IDE_DEV_NAMEBUFLEN];
    char secondary_namebuf[PCI_IDE_DEV_NAMEBUFLEN];
};

static int
ide_pci_probe(struct pci_driver *driver, struct pci_func *func)
{
    int primary_avail = 1;
    int secondary_avail = 1;

    uint8_t progif = func->prog_if_id;
    if(!(progif & (1 << 0)))
    {
        // Primary channel is in legacy mode
#ifdef CONFIG_LEGACY_IDE
        // This should be driven by the legacy mode discovery
        primary_avail = 0;
#endif
    }

    if(!(progif & (1 << 2)))
    {
        // Secondary channel is in legacy mode
#ifdef CONFIG_LEGACY_IDE
        // This should be driven by the legacy mode discovery
        secondary_avail = 0;
#endif
    }

    if(!primary_avail && !secondary_avail)
    {
        return -EINVAL;
    }

    // We should be able to drive at least one of the channels
    return 0;
}

static int
ide_pci_init_device(struct pci_driver *driver, struct pci_func *func)
{
    int res;
    printk("IDE: init\n");

    int primary_avail = 1;
    int secondary_avail = 1;

    pio_t primary_io;
    pio_t primary_ctrl;
    pio_t secondary_io;
    pio_t secondary_ctrl;

    uint8_t progif = func->prog_if_id;

    if(primary_avail)
    {
        if(!(progif & (1 << 0)))
        {
            // Primary channel is in legacy mode
#ifdef CONFIG_LEGACY_IDE
            // This should be driven by the legacy mode discovery
            primary_avail = 0;
#else
            if(progif & (1 << 1))
            {
                // Switch off legacy mode
                do
                {
                    res = pci_func_readb(func, PCI_CFG_PROG_IF, &progif);
                    if(res)
                    {
                        primary_avail = 0;
                        break;
                    }
                    progif |= (1 << 0);
                    pci_func_writeb(func, PCI_CFG_PROG_IF, progif);
                    res = pci_func_readb(func, PCI_CFG_PROG_IF, &progif);
                    if(res)
                    {
                        primary_avail = 0;
                        break;
                    }
                    if(!(progif & (1 << 0)))
                    {
                        primary_avail = 0;
                        break;
                    }
                } while(0);
                if(func->bars[0].type != PCI_BAR_PIO)
                {
                    primary_avail = 0;
                }
                else
                {
                    primary_io = func->bars[0].pio.base;
                }
                if(func->bars[1].type != PCI_BAR_PIO)
                {
                    primary_avail = 0;
                }
                else
                {
                    primary_ctrl = func->bars[1].pio.base;
                }
            }
            else
            {
                // Use legacy mode
                primary_io = 0x1F0;
                primary_ctrl = 0x3F6;
            }
#endif
        }
    }

    if(secondary_avail)
    {
        if(!(progif & (1 << 2)))
        {
            // Secondary channel is in legacy mode
#ifdef CONFIG_LEGACY_IDE
            // This should be driven by the legacy mode discovery
            secondary_avail = 0;
#else
            if(progif & (1 << 3))
            {
                // Switch off legacy mode
                do
                {
                    res = pci_func_readb(func, PCI_CFG_PROG_IF, &progif);
                    if(res)
                    {
                        secondary_avail = 0;
                        break;
                    }
                    progif |= (1 << 2);
                    pci_func_writeb(func, PCI_CFG_PROG_IF, progif);
                    res = pci_func_readb(func, PCI_CFG_PROG_IF, &progif);
                    if(res)
                    {
                        secondary_avail = 0;
                        break;
                    }
                    if(!(progif & (1 << 2)))
                    {
                        secondary_avail = 0;
                        break;
                    }
                } while(0);

                if(func->bars[2].type != PCI_BAR_PIO)
                {
                    secondary_avail = 0;
                }
                else
                {
                    secondary_io = func->bars[2].pio.base;
                }
                if(func->bars[3].type != PCI_BAR_PIO)
                {
                    secondary_avail = 0;
                }
                else
                {
                    secondary_ctrl = func->bars[3].pio.base;
                }
            }
            else
            {
                // Use legacy mode
                secondary_io = 0x170;
                secondary_ctrl = 0x376;
            }
#endif
        }
    }

    struct pci_ide_dev *pci_ide_dev =
        kzmalloc(sizeof(struct pci_ide_dev), KM_KERNEL);
    if(pci_ide_dev == NULL)
    {
        return -ENOMEM;
    }
    func->driver_priv_state = pci_ide_dev;

    {
        snprintk(pci_ide_dev->primary_namebuf,
                 PCI_IDE_DEV_NAMEBUFLEN,
                 "%d.%d.%d.%d-ide-0",
                 (int)func->segment->segment_id,
                 (int)func->device->bus->bus_index,
                 (int)func->device->index,
                 (int)func->index);
        pci_ide_dev->primary_namebuf[PCI_IDE_DEV_NAMEBUFLEN - 1] = '\0';

        snprintk(pci_ide_dev->secondary_namebuf,
                 PCI_IDE_DEV_NAMEBUFLEN,
                 "%d.%d.%d.%d-ide-1",
                 (int)func->segment->segment_id,
                 (int)func->device->bus->bus_index,
                 (int)func->device->index,
                 (int)func->index);
        pci_ide_dev->secondary_namebuf[PCI_IDE_DEV_NAMEBUFLEN - 1] = '\0';
    }

    if(primary_avail)
    {
        res = ide_dev_register(primary_io,
                               primary_ctrl,
                               pci_ide_dev->primary_namebuf,
                               &pci_ide_dev->primary);
        if(res)
        {
            primary_avail = 0;
            pci_ide_dev->primary = NULL;
        }
    }
    if(secondary_avail)
    {
        res = ide_dev_register(secondary_io,
                               secondary_ctrl,
                               pci_ide_dev->secondary_namebuf,
                               &pci_ide_dev->secondary);
        if(res)
        {
            secondary_avail = 0;
            pci_ide_dev->secondary = NULL;
        }
    }

    if(!primary_avail && !secondary_avail)
    {
        kfree(pci_ide_dev);
        return -EINVAL;
    }

    return 0;
}

static int
ide_pci_deinit_device(struct pci_driver *driver, struct pci_func *func)
{
    int res;
    printk("IDE: deinit\n");

    struct pci_ide_dev *pci_ide_dev = func->driver_priv_state;

    if(pci_ide_dev->primary != NULL)
    {
        ide_dev_unregister(pci_ide_dev->primary);
    }
    if(pci_ide_dev->secondary != NULL)
    {
        ide_dev_unregister(pci_ide_dev->secondary);
    }

    kfree(pci_ide_dev);
    func->driver_priv_state = NULL;

    return 0;
}

static struct pci_id ide_pci_ids[] = {
    {
        .class = 0x1,
        .subclass = 0x1,
        .flags = PCI_ID_CHECK_CLASS | PCI_ID_CHECK_SUBCLASS |
                 PCI_ID_IGNORE_DEVICE | PCI_ID_IGNORE_VENDOR,
    },
};

static struct pci_driver_ops ide_pci_driver_ops = {
    .probe = &ide_pci_probe,
    .init_device = &ide_pci_init_device,
    .deinit_device = &ide_pci_deinit_device,
};

static struct pci_driver ide_pci_driver = {
    .ops = &ide_pci_driver_ops,
    .num_ids = sizeof(ide_pci_ids) / sizeof(struct pci_id),
    .ids = ide_pci_ids,
};

DECLARE_PCI_DRIVER(ide_pci_driver);
