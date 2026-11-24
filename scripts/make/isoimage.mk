ifdef CONFIG_BUILD_GRUB_ISOIMAGE

ISO_BOOT_FILES += $(OUTPUT_DIR)/kanawha.o
ISO_BOOT_FILES += $(OUTPUT_DIR)/initrd


GRUB_CFG := $(SETUPS_DIR)/$(ARCH)/grub.cfg

ISO_BUILD_DIR := $(OUTPUT_DIR)/iso
ISO_BUILD_BOOT_DIR := $(ISO_BUILD_DIR)/boot
ISO_BUILD_GRUB_DIR := $(ISO_BUILD_BOOT_DIR)/grub

ISO_BUILT_GRUB_CFG := $(ISO_BUILD_GRUB_DIR)/grub.cfg
ISO_BUILT_BOOT_FILES := $(ISO_BOOT_FILES:$(OUTPUT_DIR)/%=$(ISO_BUILD_BOOT_DIR)/%)

$(ISO_BUILD_DIR): $(ISO_BOOT_FILES) $(GRUB_CFG) FORCE
	$(Q)mkdir -p $(ISO_BUILD_DIR)
	$(Q)mkdir -p $(ISO_BUILD_BOOT_DIR)
	$(Q)mkdir -p $(ISO_BUILD_GRUB_DIR)
	$(Q)cp $(GRUB_CFG) $(ISO_BUILD_GRUB_DIR)
	$(Q)cp $(ISO_BOOT_FILES) $(ISO_BUILD_BOOT_DIR)

isoimage: kanawha.iso FORCE
kanawha.iso: $(OUTPUT_DIR)/kanawha.iso FORCE
$(OUTPUT_DIR)/kanawha.iso: $(ISO_BUILD_DIR) FORCE
	$(call qinfo, $(GRUB_MSG), $(call rel-dir, $@, $(OUTPUT_DIR)))
	$(Q)grub-mkrescue -o $@ $(ISO_BUILD_DIR) $(QPIPE) $(QIGNORE)

endif
