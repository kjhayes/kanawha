ifndef __KANAWHA_INITRD_MK__
define __KANAWHA_INITRD_MK__
endef

INITRD_OUTPUT_DIR := $(OUTPUT_DIR)/initrd-root

# Ensure that the module output dir exists
$(shell mkdir -p $(MODULE_OUTPUT_DIR))
$(shell mkdir -p $(INITRD_OUTPUT_DIR))

mod-objs := $(shell find $(MODULE_OUTPUT_DIR) -name "*.ko")

ifneq ($(mod-objs),)
rel-mod-objs := $(call rel-file, $(mod-objs), $(MODULE_OUTPUT_DIR))
else
rel-mod-objs :=
endif

cpio-mod-objs := $(foreach obj,$(rel-mod-objs),$(subst /,-,$(obj)))

$(foreach obj, $(rel-mod-objs), $(shell cp $(MODULE_OUTPUT_DIR)/$(obj) $(INITRD_OUTPUT_DIR)/$(subst /,-,$(obj)) $(QPIPE)))

$(OUTPUT_DIR)/index.initrd: FORCE
	$(Q)echo $(cpio-mod-objs) > $@

initrd: $(OUTPUT_DIR)/initrd
$(OUTPUT_DIR)/initrd: $(OUTPUT_DIR)/index.initrd $(INITRD_OUTPUT_DIR)
	$(call qinfo, CPIO, $(call rel-dir, $@, $(OUTPUT_DIR)))
	$(Q)cat $< | cpio -o \
		--no-absolute-filenames \
		-D $(INITRD_OUTPUT_DIR) \
		-H bin > $@ $(QEPIPE)
	$(Q)echo $(call rel-file, $<, $(OUTPUT_DIR)) | cpio -oA \
		--no-absolute-filenames \
		-D $(OUTPUT_DIR) \
		-H bin \
		-O $@ $(QEPIPE)

endif
