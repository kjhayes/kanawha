ifndef __KANAWHA_ASM_MK__
define __KANAWHA_ASM_MK__
endef

-include $(MK_SCRIPTS_DIR)/include.mk

KERNEL_OBJDUMPFLAGS += -Sd

ifdef KERNEL_OBJDUMP

asm: kanawha.asm
kanawha.asm: $(OUTPUT_DIR)/kanawha.asm
$(OUTPUT_DIR)/kanawha.asm: $(OUTPUT_DIR)/kanawha.o
	$(call qinfo, KERNEL_OBJDUMP, $(call rel-dir, $@, $(OUTPUT_DIR)))
	$(Q)$(KERNEL_OBJDUMP) $(KERNEL_OBJDUMPFLAGS) $< > $@
endif

endif
