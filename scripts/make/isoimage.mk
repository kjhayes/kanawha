ifdef CONFIG_BUILD_GRUB_ISOIMAGE

ISO_BOOT_FILES += $(OUTPUT_DIR)/kanawha.o
ISO_BOOT_FILES += $(OUTPUT_DIR)/initrd

GRUB_CFG := $(SETUPS_DIR)/$(ARCH)/grub.cfg

ISO_BUILD_DIR := $(OUTPUT_DIR)/iso

$(ISO_BUILD_DIR): $(ISO_BOOT_FILES) $(GRUB_CFG) FORCE
	mkdir -p $@
	mkdir -p $@/boot
	mkdir -p $@/boot/grub
	cp $(GRUB_CFG) $@/boot/grub/
	cp $(ISO_BOOT_FILES) $@/boot/

isoimage: kanawha.iso FORCE
kanawha.iso: $(OUTPUT_DIR)/kanawha.iso FORCE
$(OUTPUT_DIR)/kanawha.iso: $(ISO_BUILD_DIR) FORCE
	grub-mkrescue -o $@ $(ISO_BUILD_DIR)

endif
