ifndef __KANAWHA_INITRD_MK__
define __KANAWHA_INITRD_MK__
endef

INITRD_BUILD := $(OUTPUT_DIR)/initrd-build
INITRD_EXTRA := $(ROOT_DIR)/initrd-extra

$(INITRD_BUILD): $(OUTPUT_DIR) user
	mkdir -p $@
	if [ -d $(OUTPUT_DIR)/sysroot ]; then \
	    cp -r $(OUTPUT_DIR)/sysroot/bin/* $@; \
	fi
	if [ -d $(ROOT_DIR)/initrd-extra ]; then \
	    cp -r $(ROOT_DIR)/initrd-extra/* $@; \
	fi

initrd: $(OUTPUT_DIR)/initrd
$(OUTPUT_DIR)/initrd: $(INITRD_BUILD) FORCE
	$(call qinfo, CPIO, $(call rel-dir, $@, $(OUTPUT_DIR)))
	ls $< | \
		cpio -o \
        --no-absolute-filenames \
		-D $< \
		-H bin \
		> $@

endif
