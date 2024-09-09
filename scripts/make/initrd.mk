ifndef __KANAWHA_INITRD_MK__
define __KANAWHA_INITRD_MK__
endef

INITRD_ROOT := $(ROOT_DIR)/initrd

$(shell mkdir -p $(INITRD_ROOT))

initrd: $(OUTPUT_DIR)/initrd
$(OUTPUT_DIR)/initrd: $(INITRD_ROOT) $(INITRD_OUTPUT_DIR) FORCE
	$(call qinfo, CPIO, $(call rel-dir, $@, $(OUTPUT_DIR)))
	ls $< | \
		cpio -o \
        --no-absolute-filenames \
		-D $< \
		-H bin \
		> $@ $(QEPIPE)

endif
