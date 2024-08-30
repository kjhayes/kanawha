#ifndef __KANAWHA__ARCH_X64_XAPIC_H__
#define __KANAWHA__ARCH_X64_XAPIC_H__

#include <kanawha/stdint.h>
#include <arch/x64/lapic.h>

int
xapic_provide_mmio_base(paddr_t base);

int
xapic_setup_lapic(struct lapic *apic);

#endif
