#ifndef __KANAWHA__PCI_PORT_CAM_H__
#define __KANAWHA__PCI_PORT_CAM_H__

#include <kanawha/pio.h>
#include <drivers/pci/pci.h>
#include <drivers/pci/cfg.h>

struct port_pci_cam {
    struct pci_cam cam;
    pio_t addr_port;
    pio_t data_port;
};

int
register_port_pci_cam(
        struct port_pci_cam *cam,
        pio_t addr_port,
        pio_t data_port);

#endif
