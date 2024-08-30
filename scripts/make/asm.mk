ifndef __KANAWHA_ASM_MK__
define __KANAWHA_ASM_MK__
endef

-include $(MK_SCRIPTS_DIR)/include.mk

ifdef OBJDUMP
asm: $(OUTPUT_DIR)/kanawha.asm
$(OUTPUT_DIR)/kanawha.asm: $(OUTPUT_DIR)/kanawha.o
	$(call qinfo, OBJDUMP, $(call rel-dir, $@, $(OUTPUT_DIR)))
	$(Q)$(OBJDUMP) -d $< > $@
endif

endif
