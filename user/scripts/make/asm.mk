ifndef __ELK_ASM_MK__
define __ELK_ASM_MK__
endef

-include $(MK_SCRIPTS_DIR)/include.mk

ifdef OBJDUMP
asm: elk.asm
elk.asm: $(OUTPUT_DIR)/elk.asm
$(OUTPUT_DIR)/elk.asm: $(OUTPUT_DIR)/elk.o
	$(call qinfo, OBJDUMP, $(call rel-dir, $@, $(OUTPUT_DIR)))
	$(Q)$(OBJDUMP) -D $< > $@
endif

endif
