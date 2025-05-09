#ifndef __KANAWHA__PCI_PCI_H__
#define __KANAWHA__PCI_PCI_H__

#include <kanawha/types.h>
#include <kanawha/list.h>
#include <kanawha/ops.h>
#include <kanawha/ptree.h>

#include <drivers/pci/bar.h>
#include <kanawha/irq_domain.h>
#include <kanawha/irq_dev.h>

#ifdef CONFIG_SYSFS_PCI
#include <kanawha/fs/flat.h>
#endif

#define PCI_MAX_BUSES_PER_SEGMENT (1ULL<<8)
#define PCI_MAX_DEVICES_PER_BUS  (1ULL<<5)
#define PCI_MAX_FUNC_PER_DEVICE  (1ULL<<3)

struct pci_cam;

struct pci_segment
{
    uint16_t segment_id;

    ilist_node_t global_node;

    ilist_t bus_list;
};

struct pci_bus
{
    struct pci_segment *segment;

    ilist_node_t segment_node;

    ilist_t device_list;

    uint8_t bus_index;
};

struct pci_device
{
    struct pci_segment *segment;
    struct pci_bus *bus;

    ilist_node_t bus_node;
    ilist_node_t driver_node;

    ilist_t function_list;
    uint8_t index;
};

struct pci_func
{
    struct pci_segment *segment;
    struct pci_device *device;
    struct pci_driver *driver;

    ilist_node_t global_node;
    ilist_node_t device_node;
    ilist_node_t driver_node;

    uint8_t index;

    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t class_id;
    uint8_t subclass_id;
    uint8_t prog_if_id;

    struct pci_bar bars[6];

    enum {
        PCI_IRQ_MODE_NONE = 0,
        PCI_IRQ_MODE_INTX,
        PCI_IRQ_MODE_MSI,
        PCI_IRQ_MODE_MSIX,
    } irq_mode;

    struct pci_msi_info *msi_info;
    struct pci_msix_info *msix_info;

    struct irq_domain *irq_domain;
    struct irq_dev *irq_dev;

    ilist_t cap_list;

#ifdef CONFIG_SYSFS_PCI
    struct flat_node flat_node;
#endif
};

// By default pci_ids only match against "vendor" and "device"
#define PCI_ID_CHECK_CLASS    (1ULL<<0)
#define PCI_ID_CHECK_SUBCLASS (1ULL<<1)
#define PCI_ID_CHECK_PROG_IF  (1ULL<<2)
#define PCI_ID_IGNORE_VENDOR  (1ULL<<3)
#define PCI_ID_IGNORE_DEVICE  (1ULL<<4)

struct pci_id
{
    uint16_t vendor;
    uint16_t device;

    uint8_t class;
    uint8_t subclass;
    uint8_t prog_if;

    unsigned long flags;
};

// Returns zero if this driver can control the device
// (Should assume pci_id(s) have been matched already)
#define PCI_DRIVER_PROBE_SIG(RET,ARG)\
RET(int)\
ARG(struct pci_func *, dev)

// Called to initialize the device after a successful probe
// Returns 0 on success
#define PCI_DRIVER_INIT_DEVICE_SIG(RET,ARG)\
RET(int)\
ARG(struct pci_func *, dev)

// Called after a successful "init" to deinitialize the device
// Returns 0 on success
#define PCI_DRIVER_DEINIT_DEVICE_SIG(RET,ARG)\
RET(int)\
ARG(struct pci_func *, dev)

#define PCI_DRIVER_OP_LIST(OP, ...)\
OP(probe, PCI_DRIVER_PROBE_SIG, ##__VA_ARGS__)\
OP(init_device, PCI_DRIVER_INIT_DEVICE_SIG, ##__VA_ARGS__)\
OP(deinit_device, PCI_DRIVER_DEINIT_DEVICE_SIG, ##__VA_ARGS__)

struct pci_driver;

struct pci_driver_ops {
DECLARE_OP_LIST_PTRS(PCI_DRIVER_OP_LIST, struct pci_driver *)
};

struct pci_driver
{
    // Internal Fields
    ilist_node_t global_node;
    ilist_t devices;

    // External Fields (set by driver author)
    struct pci_driver_ops *ops;
    size_t num_ids;
    struct pci_id *ids;
};

DEFINE_OP_LIST_WRAPPERS(
        PCI_DRIVER_OP_LIST,
        static inline,
        /* No Prefix */,
        pci_driver,
        ->ops->,
        SELF_ACCESSOR)

#undef PCI_DRIVER_PROBE_SIG
#undef PCI_DRIVER_INIT_DEVICE_SIG
#undef PCI_DRIVER_DEINIT_DEVICE_SIG
#undef PCI_DRIVER_OP_LIST

int
pci_probe_bus(
        struct pci_segment *segment,
        uint8_t bus_index);
int
pci_probe_device(
        struct pci_bus *bus,
        uint8_t device_index);
int
pci_probe_func(
        struct pci_device *device,
        uint8_t function);

int
register_pci_cam(
        struct pci_cam *cam,
        unsigned long flags);

int
register_pci_driver(
        struct pci_driver *driver);

int
register_pci_func(
        struct pci_func *func);

#endif
