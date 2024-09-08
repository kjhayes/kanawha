
obj-y += \
	asm/ \
	init.o \
	gdt.o \
	fpu.o \
	common.o \
	irq.o \
	idt.o \
	cpu.o \
	percpu.o \
	pic.o \
	lapic.o \
	xapic.o \
	apic_timer.o \
	ioapic.o \
	vmem.o \
	thread.o \
	stack.o \
	usermode.o \
	syscall.o \
	exception.o \
	smp.o \
	acpi.o \
	xcall.o \
	vendor.o

obj-$(CONFIG_X64_MULTIBOOT2_BOOT) += mb2_boot.o

obj-$(CONFIG_X64_BOOT_VGA) += boot_vga.o
obj-$(CONFIG_X64_BOOT_SERIAL) += boot_serial.o

obj-$(CONFIG_X64_TEST_VOLATILITY_THREAD) += volatile_thread.o

