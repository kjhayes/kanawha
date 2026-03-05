#ifndef __KANAWHA__ARCH_X64__LAPIC_PCI_MAILBOX_H__
#define __KANAWHA__ARCH_X64__LAPIC_PCI_MAILBOX_H__

#include <arch/x64/lapic.h>

int
register_cpu_lapic_pci_mailbox(struct lapic *lapic);

#endif
