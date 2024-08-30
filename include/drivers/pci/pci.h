#ifndef __KANAWHA__PCI_PCI_H__
#define __KANAWHA__PCI_PCI_H__

#include <kanawha/device.h>
#include <kanawha/stdint.h>
#include <kanawha/list.h>
#include <kanawha/ops.h>
#include <kanawha/ptree.h>

#define PCI_MAX_BUSES_PER_DOMAIN (1ULL<<8)
#define PCI_MAX_DEVICES_PER_BUS  (1ULL<<6)
#define PCI_MAX_FUNC_PER_DEVICE  (1ULL<<3)

struct pci_domain
{
    struct device dev;

    size_t domain_id;
    struct pci_cam *cam;

    ilist_node_t list_node;
};

struct pci_bus
{
    struct device dev;

    struct pci_domain *domain;

    uint8_t bus_index;
};

// One struct pci_device per PCI function
struct pci_device
{
    struct device dev;

    struct pci_domain *domain;
    struct pci_bus *bus;

    uint8_t dev_index;
    uint8_t func_index;

    uint16_t vendor_id;
    uint16_t device_id;
};

struct pci_device_id {
    uint16_t vendor;
    uint16_t device;
};

#define PCI_DRIVER_PROBE_SIG(RET,ARG)\
RET(int)\
ARG(struct pci_device *, dev)

#define PCI_DRIVER_INIT_DEVICE_SIG(RET,ARG)\
RET(int)\
ARG(struct pci_device *, dev)

#define PCI_DRIVER_DEINIT_DEVICE_SIG(RET,ARG)\
RET(int)\
ARG(struct pci_device *, dev)

#define PCI_DRIVER_OP_LIST(OP, ...)\
OP(probe, PCI_DRIVER_PROBE_SIG, ##__VA_ARGS__)\
OP(init_device, PCI_DRIVER_INIT_DEVICE_SIG, ##__VA_ARGS__)\
OP(deinit_device, PCI_DRIVER_DEINIT_DEVICE_SIG, ##__VA_ARGS__)

struct pci_driver
{
DECLARE_OP_LIST_PTRS(PCI_DRIVER_OP_LIST, struct pci_driver *)

    struct pci_device_id ids[];
};

DEFINE_OP_LIST_WRAPPERS(
        PCI_DRIVER_OP_LIST,
        static inline,
        /* No Prefix */,
        pci_driver,
        ->,
        SELF_ACCESSOR)

#undef PCI_DRIVER_PROBE_SIG
#undef PCI_DRIVER_INIT_DEVICE_SIG
#undef PCI_DRIVER_DEINIT_DEVICE_SIG
#undef PCI_DRIVER_OP_LIST

int
register_pci_domain(
        struct pci_domain *domain,
        struct pci_cam *cam);

#endif
