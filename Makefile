
export

ROOT_DIR := $(shell pwd)
SCRIPTS_DIR := $(ROOT_DIR)/scripts
MK_SCRIPTS_DIR := $(SCRIPTS_DIR)/make

KERNEL_DIR := $(ROOT_DIR)/kernel
ARCH_ROOT_DIR := $(ROOT_DIR)/arch
DRIVER_DIR := $(ROOT_DIR)/drivers
USER_DIR := $(ROOT_DIR)/user

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
ifdef CONFIG_RISCV64
	ARCH := riscv64
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

ifdef CONFIG_DEBUG_SYMBOLS
KERNEL_COMMON_FLAGS += -g
endif

KERNEL_COMMON_FLAGS += \
				-D__KANAWHA__ \
				-DKANAWHA_BUILDING_KERNEL \
				-I $(INCLUDE_DIR) \
				-include $(KERNEL_AUTOCONF) \
				$(subst ",,$(CONFIG_OPT_FLAGS)) \
				-nostdlib \
				-ffreestanding \
				-fno-pie \
				-Wall \
				-Wno-unused-variable \
				-Werror \

AFLAGS += -D__ASSEMBLER__

-include $(MK_SCRIPTS_DIR)/link.mk

KERNEL_SOURCE_DIRS := $(KERNEL_DIR) \
					  $(ARCH_KERNEL_DIR)\
					  $(DRIVER_DIR)

define build_kernel_directory =
$$(OUTPUT_DIR)/$(1)/obj.o: $$(KERNEL_AUTOCONF) $$(LDDEPS) FORCE
	$$(Q)$$(MAKE) -C $(ROOT_DIR)/$(1) -f $$(MK_SCRIPTS_DIR)/kernelbuild.mk obj 
endef
$(foreach DIR,$(KERNEL_SOURCE_DIRS), $(eval $(call build_kernel_directory,$(call rel-dir, $(DIR), $(ROOT_DIR)))))

define build_module_directory =
$(1)/modules: $$(KERNEL_AUTOCONF) $$(LDDEPS) FORCE
	$$(Q)$$(MAKE) -C $(1) -f $$(MK_SCRIPTS_DIR)/modules.mk obj
endef
$(foreach DIR,$(KERNEL_SOURCE_DIRS), $(eval $(call build_module_directory,$(DIR))))

KERNEL_OBJS := $(foreach DIR,$(KERNEL_SOURCE_DIRS),$(OUTPUT_DIR)/$(call rel-dir, $(DIR), $(ROOT_DIR))/obj.o)
KERNEL_MOD_RULES := $(foreach DIR,$(KERNEL_SOURCE_DIRS),$(DIR)/modules)

$(OUTPUT_DIR)/kanawha.o: $(KERNEL_OBJS) $(LDDEPS) | $(OUTPUT_DIR)
	$(call qinfo, LD, $(call rel-dir, $@, $(OUTPUT_DIR)))
	$(Q)$(KERNEL_LD) -T $(LD_SCRIPT) $(KERNEL_OBJS) -o $@ $(LDFLAGS) $(KERNEL_LDFLAGS)

kanawha: $(OUTPUT_DIR)/kanawha.o

binary: kanawha.bin FORCE
kanawha.bin: $(OUTPUT_DIR)/kanawha.bin FORCE
$(OUTPUT_DIR)/kanawha.bin: $(OUTPUT_DIR)/kanawha.o
	$(call qinfo, OBJCOPY, $(call rel-dir, $@, $(OUTPUT_DIR)))
	$(Q)$(KERNEL_OBJCOPY) -O binary $< $@

user: $(KERNEL_AUTOCONF) $(LDDEPS) $(USER_DIR) FORCE
	$(Q)$(MAKE) -C $(USER_DIR) -f $(MK_SCRIPTS_DIR)/user.mk

kernel: kanawha
all: kanawha user FORCE

DEFAULT_BUILD_RULE ?= all
default: $(DEFAULT_BUILD_RULE)

modules: $(KERNEL_MOD_RULES) FORCE

-include $(MK_SCRIPTS_DIR)/asm.mk
-include $(MK_SCRIPTS_DIR)/initrd.mk

clean: FORCE
	$(Q)find $(OUTPUT_DIR) -name "*.o" -delete $(QPIPE) $(QIGNORE)
	$(Q)find $(OUTPUT_DIR) -name "*.d" -delete $(QPIPE) $(QIGNORE)
	$(Q)find $(OUTPUT_DIR)/uapi -name "*.h" -delete $(QPIPE) $(QIGNORE)
	$(Q)rm $(LD_SCRIPT) $(QPIPE) $(QIGNORE)
	$(Q)rm $(KERNEL_AUTOCONF) $(QPIPE) $(QIGNORE)
	$(Q)rm -r $(OUTPUT_DIR) $(QPIPE) $(QIGNORE)

endif
endif

