ifndef __KANAWHA_ASM_MK__
define __KANAWHA_ASM_MK__
endef

-include $(MK_SCRIPTS_DIR)/include.mk

OBJDUMPFLAGS += -S

ifdef OBJDUMP

asm: kanawha.asm
kanawha.asm: $(OUTPUT_DIR)/kanawha.asm
$(OUTPUT_DIR)/kanawha.asm: $(OUTPUT_DIR)/kanawha.o
	$(call qinfo, OBJDUMP, $(call rel-dir, $@, $(OUTPUT_DIR)))
	$(Q)$(OBJDUMP) $(OBJDUMPFLAGS) $< > $@
endif

endif
