#ifndef __KANAWHA__ARCH_RISCV64__SBI_IPI_H__
#define __KANAWHA__ARCH_RISCV64__SBI_IPI_H__

#include <arch/riscv64/cpu.h>

int
sbi_send_ipi(hartid_t hartid);

#endif
