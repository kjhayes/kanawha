
obj-y += asm/

obj-y += \
	init.o \
	identity_map.o \
	irq.o \
	common.o \
	thread.o \
	usermode.o \
	percpu.o \
	cpu.o \
	mem_flags.o \
	trap.o \
	page_fault.o \
	sbi_ipi.o \
	sbi_timer.o \
	sbi_hsm.o \
	hlic.o \
	smp.o \
	syscall.o \
	fpu.o \

obj-$(CONFIG_RISCV64_SBI_DEBUG_CONSOLE) += sbi_console.o

obj-$(CONFIG_RISCV64_IMPLEMENT_VMEM_DIRECTLY) += vmem.o
obj-$(CONFIG_PAGING) += paging.o
