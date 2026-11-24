
binary: kanawha.bin FORCE
kanawha.bin: $(OUTPUT_DIR)/kanawha.bin FORCE
$(OUTPUT_DIR)/kanawha.bin: $(OUTPUT_DIR)/kanawha.o
	$(call qinfo, $(OBJCOPY_MSG), $(call rel-dir, $@, $(OUTPUT_DIR)))
	$(Q)$(KERNEL_OBJCOPY) -O binary $< $@

