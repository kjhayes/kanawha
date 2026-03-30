
export

default:
	@

-include $(MK_SCRIPTS_DIR)/include.mk

USER_SYSROOT_DIR := $(OUTPUT_DIR)/sysroot
USER_SYSROOT_INCLUDE_DIR := $(USER_SYSROOT_DIR)/include
USER_SYSROOT_LIB_DIR := $(USER_SYSROOT_DIR)/lib
USER_SYSROOT_BIN_DIR := $(USER_SYSROOT_DIR)/bin

CUR_OUTPUT_DIR := $(OUTPUT_DIR)/user

$(shell mkdir -p $(CUR_OUTPUT_DIR))
$(shell mkdir -p $(CUR_OUTPUT_DIR)/lib)
$(shell mkdir -p $(CUR_OUTPUT_DIR)/bin)
$(shell mkdir -p $(USER_SYSROOT_DIR))
$(shell mkdir -p $(USER_SYSROOT_INCLUDE_DIR))
$(shell mkdir -p $(USER_SYSROOT_LIB_DIR))
$(shell mkdir -p $(USER_SYSROOT_BIN_DIR))

uapi: $(CUR_OUTPUT_DIR)/kanawha.api FORCE
$(CUR_OUTPUT_DIR)/kanawha.api: $(KERNEL_AUTOCONF) $(INCLUDE_DIR)/kanawha/uapi/
	$(call qinfo, CP, $(call rel-dir, $(USER_SYSROOT_INCLUDE_DIR)/kanawha/\*, $(OUTPUT_DIR)))
	$(Q)cp -RT $(INCLUDE_DIR)/kanawha/uapi $(USER_SYSROOT_INCLUDE_DIR)/kanawha
	$(call qinfo, CP, $(call rel-dir, $(USER_SYSROOT_INCLUDE_DIR)/kanawha/kanawha-config.h, $(OUTPUT_DIR)))
	$(Q)cp $(KERNEL_AUTOCONF) $(USER_SYSROOT_INCLUDE_DIR)/kanawha/kanawha-config.h
	$(call qinfo, TOUCH, $(call rel-dir, $@, $(OUTPUT_DIR)))
	$(Q)touch $@

USER_COMMON_FLAGS += \
	-I$(USER_SYSROOT_INCLUDE_DIR) \

USER_LDFLAGS += \
	-L $(USER_SYSROOT_LIB_DIR)

CUR_SOURCE_DIR := $(shell pwd)/

-include $(CUR_SOURCE_DIR)/Makefile

define build-lib =

$$(CUR_OUTPUT_DIR)/lib/$(1)/obj.o: uapi userincludes FORCE
	$$(Q)$$(MAKE) -C $$(CUR_SOURCE_DIR)/lib/$(1) -f $$(MK_SCRIPTS_DIR)/userbuild.mk obj

userlibs: $$(USER_SYSROOT_LIB_DIR)/lib$(1).a
$$(USER_SYSROOT_LIB_DIR)/lib$(1).a: $$(CUR_OUTPUT_DIR)/lib/$(1)/obj.o
	$$(call qinfo, USER_LD, $$(call rel-dir, $$@, $$(OUTPUT_DIR)))
	$$(Q)$$(USER_LD) -r $$(USER_LDFLAGS) $$(LDFLAGS) \
		$$(CUR_OUTPUT_DIR)/lib/$(1)/obj.o -o $$(USER_SYSROOT_LIB_DIR)/lib$(1).a
endef

define include-lib =

userincludes: $$(CUR_OUTPUT_DIR)/lib/$(1).api
$$(CUR_OUTPUT_DIR)/lib/$(1).api: $$(CUR_SOURCE_DIR)/lib/$(1)/include
	$$(call qinfo, CP, $$(call rel-dir, $$(USER_SYSROOT_INCLUDE_DIR)/$(1), $$(OUTPUT_DIR)))
	$$(Q)cp -RT $$(CUR_SOURCE_DIR)/lib/$(1)/include $$(USER_SYSROOT_INCLUDE_DIR)
	$$(call qinfo, TOUCH, $$(call rel-dir, $$@, $$(OUTPUT_DIR)))
	$$(Q)touch $$@

endef

define build-bin =

$(CUR_OUTPUT_DIR)/bin/$(1)/obj.o: uapi userincludes userlibs FORCE
	$(Q)$(MAKE) -C $(CUR_SOURCE_DIR)/bin/$(1) -f $(MK_SCRIPTS_DIR)/userbuild.mk obj

userbins: $$(USER_SYSROOT_BIN_DIR)/$(1)
$$(USER_SYSROOT_BIN_DIR)/$(1): $$(CUR_OUTPUT_DIR)/bin/$(1)/obj.o
	$$(call qinfo, USER_LD, $$(call rel-dir, $$@, $$(OUTPUT_DIR)))
	$$(Q)$$(USER_LD) $$(USER_LDFLAGS) $$(LDFLAGS) \
		$$(CUR_OUTPUT_DIR)/bin/$(1)/obj.o -o $$(USER_SYSROOT_BIN_DIR)/$(1) \
		-lwindd -lkfb -lcrt -lc

endef

$(foreach lib,$(libs),$(eval $(call build-lib,$(lib))))
$(foreach lib,$(libs),$(eval $(call include-lib,$(lib))))
$(foreach bin,$(bins),$(eval $(call build-bin,$(bin))))

userincludes:
	@

userlibs: 
	@

userbins:
	@

default: userlibs userbins FORCE

