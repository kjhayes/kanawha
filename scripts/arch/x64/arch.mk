
COMMON_FLAGS += -mcmodel=large

QEMU_DEPS += $(OUTPUT_DIR)/kanawha.iso
QEMU := qemu-system-x86_64 -cdrom $(OUTPUT_DIR)/kanawha.iso

ISO_BOOT_FILES += $(OUTPUT_DIR)/kanawha.o
ISO_BOOT_FILES += $(SETUPS_DIR)/x64/init.bin
ISO_BOOT_FILES += $(OUTPUT_DIR)/initrd

isofs: $(ISO_BOOT_FILES) $(SETUPS_DIR)/x64/grub.cfg FORCE
	$(Q)mkdir -p $(OUTPUT_DIR)/iso
	$(Q)mkdir -p $(OUTPUT_DIR)/iso/boot
	$(Q)mkdir -p $(OUTPUT_DIR)/iso/boot/grub
	$(Q)cp $(SETUPS_DIR)/x64/grub.cfg $(OUTPUT_DIR)/iso/boot/grub/
	$(Q)cp $(ISO_BOOT_FILES) $(OUTPUT_DIR)/iso/boot/

isoimage: kanawha.iso FORCE
kanawha.iso: $(OUTPUT_DIR)/kanawha.iso FORCE
$(OUTPUT_DIR)/kanawha.iso: isofs FORCE
	$(Q)grub-mkrescue -o $@ $(OUTPUT_DIR)/iso $(QPIPE)

FORCE:

