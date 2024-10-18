#ifndef __KANAWHA__PCI_PCI_H__
#define __KANAWHA__PCI_PCI_H__

#include <kanawha/device.h>
#include <kanawha/stdint.h>
#include <kanawha/list.h>
#include <kanawha/ops.h>
#include <kanawha/ptree.h>
#include <kanawha/pio.h>
#include <kanawha/mmio.h>

#define PCI_MAX_BUSES_PER_DOMAIN (1ULL<<8)
#define PCI_MAX_DEVICES_PER_BUS  (1ULL<<6)
#define PCI_MAX_FUNC_PER_DEVICE  (1ULL<<3)

struct pci_domain
{
    size_t domain_id;

    // Configuration Access Mechanism
    struct pci_cam *cam;

    ilist_node_t global_node;

    ilist_t bus_list;
};

struct pci_bus
{
    struct pci_domain *domain;

    ilist_node_t domain_node;

    ilist_t device_list;

    uint8_t bus_index;
};

struct pci_device
{
    struct pci_domain *domain;
    struct pci_bus *bus;

    ilist_node_t bus_node;
    ilist_node_t driver_node;

    ilist_t function_list;
    uint8_t index;
};

struct pci_bar
{
    size_t size;
    uint64_t phys_addr;

    enum
    {
        PCI_BAR_NONE = 0,
        PCI_BAR_MMIO,
        PCI_BAR_PIO,
    } type;

    union
    {
        struct
        {
            void __mmio *base;
            unsigned prefetch : 1;
            unsigned type : 2;
        } mmio;

        struct
        {
            pio_t base;
        } pio;
    };
};

uint8_t  pci_bar_readb(struct pci_bar *bar, size_t offset);
uint16_t pci_bar_readw(struct pci_bar *bar, size_t offset);
uint32_t pci_bar_readl(struct pci_bar *bar, size_t offset);
uint64_t pci_bar_readq(struct pci_bar *bar, size_t offset);

void pci_bar_writeb(struct pci_bar *bar, size_t offset, uint8_t  val);
void pci_bar_writew(struct pci_bar *bar, size_t offset, uint16_t val);
void pci_bar_writel(struct pci_bar *bar, size_t offset, uint32_t val);
void pci_bar_writeq(struct pci_bar *bar, size_t offset, uint64_t val);

struct pci_func
{
    struct pci_domain *domain;
    struct pci_device *device;
    struct pci_driver *driver;

    ilist_node_t global_node;
    ilist_node_t device_node;

    uint8_t index;

    uint16_t vendor_id;
    uint16_t device_id;

    struct pci_bar bars[6];
};

struct pci_id {
    uint16_t vendor;
    uint16_t device;
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
        struct pci_domain *domain,
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
register_pci_domain(
        struct pci_domain *domain,
        struct pci_cam *cam);

int
register_pci_driver(
        struct pci_driver *driver);

int
register_pci_func(
        struct pci_func *func);

#endif
