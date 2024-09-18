
export

ROOT_DIR := $(shell pwd)
SCRIPTS_DIR := $(ROOT_DIR)/scripts
MK_SCRIPTS_DIR := $(SCRIPTS_DIR)/make

KERNEL_DIR := $(ROOT_DIR)/kernel
ARCH_ROOT_DIR := $(ROOT_DIR)/arch
DRIVER_DIR := $(ROOT_DIR)/drivers

INCLUDE_DIR := $(ROOT_DIR)/include

LINK_DIR := $(ROOT_DIR)/link
SETUPS_DIR := $(ROOT_DIR)/setups
OUTPUT_DIR := $(ROOT_DIR)/build
MODULE_OUTPUT_DIR := $(OUTPUT_DIR)/modules

PYTHON := python3


default:
	@

$(OUTPUT_DIR): FORCE
	$(Q)mkdir -p $@

include $(MK_SCRIPTS_DIR)/include.mk
include $(MK_SCRIPTS_DIR)/config.mk

ifeq ($(findstring config,$(MAKECMDGOALS)),config)
# Don't try to do anything if the goal includes the substring "config"
else
ifndef CONFIG_KANAWHA

default: missing_config_message

missing_config_message: FORCE
	@echo Could Not Find .config File! Run "make menuconfig" or "make defconfig"!

else

ifdef CONFIG_X64
	ARCH := x64
endif

ifdef ARCH
-include $(SCRIPTS_DIR)/arch/$(ARCH)/arch.mk
else
	$(error "No Architecture Specified!")
endif

ifdef CONFIG_CLANG
	TOOLCHAIN := clang
endif
ifdef CONFIG_GCC
	TOOLCHAIN := gcc
endif

ifdef TOOLCHAIN
-include $(SCRIPTS_DIR)/toolchain/$(TOOLCHAIN)/toolchain.mk
else
	$(error "No Toolchain Specified!")
endif

ARCH_KERNEL_DIR := $(ARCH_ROOT_DIR)/$(ARCH)

COMMON_FLAGS += \
				-D__KANAWHA__ \
				-I $(INCLUDE_DIR) \
				-include $(AUTOCONF) \
				$(subst ",,$(CONFIG_OPT_FLAGS)) \
				-fno-pie \
				-fno-pic \
				-nostdlib \
				-nostdinc
COMMON_DEPS += $(AUTOCONF)
AFLAGS += -D__ASSEMBLER__
CFLAGS += -mgeneral-regs-only

ifdef CONFIG_DEBUG_SYMBOLS
COMMON_FLAGS += -g
endif

LDFLAGS += $(OUTPUT_DIR)/null.o
LDDEPS += $(OUTPUT_DIR)/null.o
$(OUTPUT_DIR)/null.o: $(SCRIPTS_DIR)/null.c $(CDEPS) $(COMMON_DEPS) | $(OUTPUT_DIR)
	$(call qinfo, CC, $(call rel-dir, $@, $(OUTPUT_DIR)))
	$(Q)$(CC) -c $(CFLAGS) $(COMMON_FLAGS) $< -o $@

LD_SCRIPT_H := $(LINK_DIR)/kanawha.$(ARCH).ldh
LD_SCRIPT := $(OUTPUT_DIR)/kanawha.$(ARCH).ld
$(LD_SCRIPT): $(LD_SCRIPT_H) $(COMMON_DEPS) | $(OUTPUT_DIR)
	$(call qinfo, CPP, $(call rel-dir, $@, $(OUTPUT_DIR)))
	$(Q)$(CPP) $(COMMON_FLAGS) $< -o $@

LDDEPS += $(LD_SCRIPT)

KERNEL_SOURCE_DIRS := $(KERNEL_DIR) \
					  $(ARCH_KERNEL_DIR)

define build_kernel_directory =
$$(OUTPUT_DIR)/$(1)/obj.o: $$(LDDEPS) FORCE
	$$(Q)$$(MAKE) -C $(ROOT_DIR)/$(1) -f $$(MK_SCRIPTS_DIR)/build.mk obj 
endef
$(foreach DIR,$(KERNEL_SOURCE_DIRS), $(eval $(call build_kernel_directory,$(call rel-dir, $(DIR), $(ROOT_DIR)))))

define build_module_directory =
$(1)/modules: $$(LDDEPS) FORCE
	$$(Q)$$(MAKE) -C $(1) -f $$(MK_SCRIPTS_DIR)/modules.mk obj
endef
$(foreach DIR,$(KERNEL_SOURCE_DIRS), $(eval $(call build_module_directory,$(DIR))))

KERNEL_OBJS := $(foreach DIR,$(KERNEL_SOURCE_DIRS),$(OUTPUT_DIR)/$(call rel-dir, $(DIR), $(ROOT_DIR))/obj.o)
KERNEL_MOD_RULES := $(foreach DIR,$(KERNEL_SOURCE_DIRS),$(DIR)/modules)

$(OUTPUT_DIR)/kanawha.o: $(KERNEL_OBJS) $(LDDEPS) | $(OUTPUT_DIR)
	$(call qinfo, LD, $(call rel-dir, $@, $(OUTPUT_DIR)))
	$(Q)$(LD) $(LDFLAGS) -T $(LD_SCRIPT) $(KERNEL_OBJS) -o $@

kanawha: $(OUTPUT_DIR)/kanawha.o

default: kanawha

modules: $(KERNEL_MOD_RULES) FORCE

-include $(MK_SCRIPTS_DIR)/qemu.mk
-include $(MK_SCRIPTS_DIR)/asm.mk
-include $(MK_SCRIPTS_DIR)/initrd.mk

clean: FORCE
	$(Q)find $(OUTPUT_DIR) -name "*.o" -delete $(QPIPE) $(QIGNORE)
	$(Q)find $(OUTPUT_DIR) -name "*.d" -delete $(QPIPE) $(QIGNORE)
	$(Q)rm $(LD_SCRIPT) $(QPIPE) $(QIGNORE)
	$(Q)rm $(AUTOCONF) $(QPIPE) $(QIGNORE)
	$(Q)rm -r $(OUTPUT_DIR) $(QPIPE) $(QIGNORE)

endif
endif

