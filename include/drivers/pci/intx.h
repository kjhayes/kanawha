#ifndef __KANAWHA__PCI_INTX_H__
#define __KANAWHA__PCI_INTX_H__

#include <drivers/pci/pci.h>

typedef enum {
    PCI_INTX_NONE = -1,
    PCI_INTX_INTA =  1,
    PCI_INTX_INTB =  2,
    PCI_INTX_INTC =  3,
    PCI_INTX_INTD =  4,
} pci_intx_pin_t;

static inline const char *
pci_intx_pin_to_string(
        pci_intx_pin_t pin)
{
    switch(pin) {
        case PCI_INTX_NONE: return "None";
        case PCI_INTX_INTA: return "INTA#";
        case PCI_INTX_INTB: return "INTB#";
        case PCI_INTX_INTC: return "INTC#";
        case PCI_INTX_INTD: return "INTD#";
        default: return "ERROR-INVALID";
    }
}

struct pci_intx_info
{
    struct pci_func *func;
    pci_intx_pin_t pin;
    struct irq_dev irq_dev;
    struct irq_domain *irq_domain;
    struct irq_action *active_link;
    struct irq_action *pin_links[4];
};

int
pci_func_init_intx_info(struct pci_func *func);

int
pci_func_deinit_intx_info(struct pci_func *func);

int
pci_func_start_intx(struct pci_func *func, size_t req_num_irqs);
int
pci_func_stop_intx(struct pci_func *func);

int
pci_func_route_intx(
        struct pci_func *func,
        pci_intx_pin_t pin,
        irq_t irq);

#endif
