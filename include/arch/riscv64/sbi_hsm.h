#ifndef __KANAWHA__ARCH_RISCV64__SBI_HSM_H__
#define __KANAWHA__ARCH_RISCV64__SBI_HSM_H__

#include <arch/riscv64/cpu.h>
#include <kanawha/pointer.h>

int
sbi_hart_start(hartid_t hartid, void __phys *start_addr, uint64_t opaque);

#define SBI_HART_STATE_STARTED (0x0)
#define SBI_HART_STATE_STOPPED (0x1)
#define SBI_HART_STATE_START_PENDING (0x2)
#define SBI_HART_STATE_STOP_PENDING (0x3)
#define SBI_HART_STATE_SUSPENDED (0x4)
#define SBI_HART_STATE_SUSPEND_PENDING (0x5)
#define SBI_HART_STATE_RESUME_PENDING (0x6)
int
sbi_hart_get_status(hartid_t hartid);

#endif
