#ifndef __KANAWHA__ARCH_X64_XAPIC_H__
#define __KANAWHA__ARCH_X64_XAPIC_H__

#include <arch/x64/lapic.h>
#include <kanawha/types.h>

int
xapic_provide_mmio_base(void __phys *base);

int
xapic_setup_lapic(struct lapic *apic);

#endif
