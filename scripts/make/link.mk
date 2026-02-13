
LDFLAGS += $(OUTPUT_DIR)/null.o
LDDEPS += $(OUTPUT_DIR)/null.o
$(OUTPUT_DIR)/null.o: $(SCRIPTS_DIR)/null.c $(CDEPS) $(KERNEL_AUTOCONF) | $(OUTPUT_DIR)
	$(call qinfo, CC, $(call rel-dir, $@, $(OUTPUT_DIR)))
	$(Q)$(KERNEL_CC) -c $(CFLAGS) $(KERNEL_CFLAGS) $(COMMON_FLAGS) $(KERNEL_COMMON_FLAGS) $< -o $@

LD_SCRIPT_H := $(LINK_DIR)/kanawha.$(ARCH).ldh
LD_SCRIPT := $(OUTPUT_DIR)/kanawha.$(ARCH).ld
$(LD_SCRIPT): $(LD_SCRIPT_H) $(KERNEL_AUTOCONF) | $(OUTPUT_DIR)
	$(call qinfo, CPP, $(call rel-dir, $@, $(OUTPUT_DIR)))
	$(Q)$(KERNEL_CPP) $(COMMON_FLAGS) $(KERNEL_COMMON_FLAGS) $< -o $@

LDDEPS += $(LD_SCRIPT)

