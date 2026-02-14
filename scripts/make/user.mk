
default:
	@

-include $(MK_SCRIPTS_DIR)/include.mk

USER_SYSROOT_DIR := $(OUTPUT_DIR)/sysroot
USER_SYSROOT_INCLUDE_DIR := $(USER_SYSROOT_DIR)/include
USER_SYSROOT_LIB_DIR := $(USER_SYSROOT_DIR)/lib
USER_SYSROOT_BIN_DIR := $(USER_SYSROOT_DIR)/bin

CUR_OUTPUT_DIR := $(OUTPUT_DIR)/user

$(shell mkdir -p $(CUR_OUTPUT_DIR))
$(shell mkdir -p $(USER_SYSROOT_DIR))
$(shell mkdir -p $(USER_SYSROOT_INCLUDE_DIR))
$(shell mkdir -p $(USER_SYSROOT_LIB_DIR))
$(shell mkdir -p $(USER_SYSROOT_BIN_DIR))

UAPI_SYSROOT_DIR := $(USER_SYSROOT_INCLUDE_DIR)/kanawha
$(shell mkdir -p $(UAPI_SYSROOT_DIR))

uapi: $(UAPI_SYSROOT_DIR)
$(UAPI_SYSROOT_DIR): $(KERNEL_AUTOCONF) $(INCLUDE_DIR)/kanawha/uapi
	$(call qinfo, CP, $(call rel-dir, $@/\*, $(OUTPUT_DIR)))
	$(Q)cp -RT $(INCLUDE_DIR)/kanawha/uapi $@
	$(call qinfo, CP, $(call rel-dir, $@/kanawha-config.h, $(OUTPUT_DIR)))
	$(Q)cp $(KERNEL_AUTOCONF) $@/kanawha-config.h

USER_COMMON_FLAGS += \
	-I$(USER_SYSROOT_INCLUDE_DIR) \

USER_LDFLAGS += \
	-L $(USER_SYSROOT_LIB_DIR)

CUR_SOURCE_DIR := $(shell pwd)/

-include $(CUR_SOURCE_DIR)/Makefile

define build-lib =

$(CUR_OUTPUT_DIR)/$(1)/obj.o: FORCE
	$(Q)$(MAKE) -C $(CUR_SOURCE_DIR)/$(1) -f $(MK_SCRIPTS_DIR)/userbuild.mk obj

userlibs: $$(USER_SYSROOT_LIB_DIR)/lib$(1).a
$$(USER_SYSROOT_LIB_DIR)/lib$(1).a: $$(CUR_OUTPUT_DIR)/$(1)/obj.o
	$$(Q)$$(USER_LD) -r $$(USER_LDFLAGS) $$(LDFLAGS) \
		$$(CUR_OUTPUT_DIR)/$(1)/obj.o -o $$(USER_SYSROOT_LIB_DIR)/lib$(1).a
endef

define include-lib =
userincludes: $$(CUR_OUTPUT_DIR)/$(1).api
$$(CUR_OUTPUT_DIR)/$(1).api: $$(CUR_SOURCE_DIR)/$(1)/include
	$$(call qinfo, CP, $$(call rel-dir, $$(USER_SYSROOT_INCLUDE_DIR)/$(1), $$(OUTPUT_DIR)))
	$$(Q)cp -RT $$(CUR_SOURCE_DIR)/$(1)/include $$(USER_SYSROOT_INCLUDE_DIR)
	$$(call qinfo, TOUCH, $$(call rel-dir, $$@, $$(OUTPUT_DIR)))
	$$(Q)touch $$@
endef

$(foreach lib,$(libs),$(eval $(call build-lib,$(lib))))
$(foreach lib,$(libs),$(eval $(call include-lib,$(lib))))

userincludes:
	@

userlibs: uapi userincludes
	@

default: userlibs FORCE

