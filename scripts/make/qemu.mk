
QEMU_FLAGS += -chardev stdio,id=chardev0,logfile=serial.log
QEMU_FLAGS += -chardev memory,id=chardev1,logfile=pciserial.log
QEMU_FLAGS += -serial chardev:chardev0
QEMU_FLAGS += -m 2G
QEMU_FLAGS += -device VGA
QEMU_FLAGS += -M hpet=on
QEMU_FLAGS += -smp 2
QEMU_FLAGS += -device virtio-serial-pci
QEMU_FLAGS += -device virtconsole,chardev=chardev1,name=console.0
QEMU_FLAGS += -accel tcg
#QEMU_FLAGS += -device edu
#QEMU_FLAGS += -device pci-testdev
#QEMU_FLAGS += -device e1000e
#QEMU_FLAGS += -display none

ifdef QEMU
qemu: $(QEMU_DEPS)
	$(Q)$(QEMU) $(QEMU_FLAGS)
qemu-gdb: $(QEMU_DEPS)
	$(Q)$(QEMU) $(QEMU_FLAGS) -gdb tcp::1234 -S -no-reboot -no-shutdown
endif

