
QEMU_FLAGS += -chardev stdio,id=chardev0,logfile=serial.log
QEMU_FLAGS += -serial chardev:chardev0
QEMU_FLAGS += -m 2G
QEMU_FLAGS += -device VGA
QEMU_FLAGS += -M hpet=on
QEMU_FLAGS += -smp 4

ifdef QEMU
qemu: $(QEMU_DEPS)
	$(Q)$(QEMU) $(QEMU_FLAGS)
qemu-gdb: $(QEMU_DEPS)
	$(Q)$(QEMU) $(QEMU_FLAGS) -gdb tcp::1234 -S -no-reboot -no-shutdown -d int
endif

