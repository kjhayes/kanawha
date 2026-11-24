
user: FORCE
	@

-include $(MK_SCRIPTS_DIR)/include.mk

USER_OUTPUT_DIR := $(OUTPUT_DIR)/user
USER_LIB_OUTPUT_DIR := $(USER_OUTPUT_DIR)/lib
USER_BIN_OUTPUT_DIR := $(USER_OUTPUT_DIR)/bin

$(shell mkdir -p $(USER_OUTPUT_DIR))
$(shell mkdir -p $(USER_LIB_OUTPUT_DIR))
$(shell mkdir -p $(USER_BIN_OUTPUT_DIR))

USER_COMMON_FLAGS += \
	-ffreestanding \
	-I$(SYSROOT_INCLUDE_DIR) \

USER_COMMON_FLAGS += -g

USER_LDFLAGS += \
	-L $(SYSROOT_LIB_DIR)

USER_SOURCE_DIR := $(ROOT_DIR)/user
USER_BIN_SOURCE_DIR := $(USER_SOURCE_DIR)/bin
USER_LIB_SOURCE_DIR := $(USER_SOURCE_DIR)/lib

-include $(USER_SOURCE_DIR)/Makefile
USER_LIB_NAMES := $(foreach lib,$(lib-y),$(strip $(lib)))
USER_BIN_NAMES := $(foreach bin,$(bin-y),$(strip $(bin)))

USER_LIB_DIRS := $(USER_LIB_NAMES:%=$(USER_LIB_SOURCE_DIR)/%)
USER_BIN_DIRS := $(USER_BIN_NAMES:%=$(USER_BIN_SOURCE_DIR)/%)

USER_LIB_INCLUDE_SOURCE_DIRS := $(wildcard $(USER_LIB_DIRS:%=%/include))

define user_include_dir_rule =

lib_headers: $(addprefix $$(SYSROOT_INCLUDE_DIR)/, $(2))
$(addprefix $$(SYSROOT_INCLUDE_DIR)/, $(2)) &: $(addprefix $(1)/, $(2))
	$$(call qinfo, $$(CP_MSG),\
		$$(call rel-dir, $(1), $$(USER_LIB_SOURCE_DIR))/**/*.h \
		-> $$(call rel-dir, $$(SYSROOT_INCLUDE_DIR), $$(OUTPUT_DIR))/)
	$$(Q)cp -RT $(1)/ $$(SYSROOT_INCLUDE_DIR)/

endef

$(foreach DIR,\
	      $(USER_LIB_INCLUDE_SOURCE_DIRS),\
		  $(eval $(call user_include_dir_rule,\
		                $(DIR),\
	                    $(foreach FILE, $(wildcard $(DIR)/*.h)\
		                                $(wildcard $(DIR)/**/*.h),\
								  $(FILE:$(DIR)/%=%))\
				   )))

define build-lib =

$$(USER_OUTPUT_DIR)/lib/$(1)/obj.o: $$(LDDEPS) uapi lib_headers FORCE
	$$(Q)$$(MAKE) -C $$(USER_LIB_SOURCE_DIR)/$(1) -f $$(MK_SCRIPTS_DIR)/userbuild.mk obj

libs: $$(SYSROOT_LIB_DIR)/lib$(1).a lib_headers
$$(SYSROOT_LIB_DIR)/lib$(1).a: $$(USER_OUTPUT_DIR)/lib/$(1)/obj.o
	$$(call qinfo, $$(ULD_MSG), $$(COLOR_BRIGHT)$$(call rel-dir, $$@, $$(OUTPUT_DIR)))$$(COLOR_NORMAL)
	$$(Q)$$(USER_LD) -r $$(USER_LDFLAGS) $$(LDFLAGS) \
		$$(USER_OUTPUT_DIR)/lib/$(1)/obj.o -o $$(SYSROOT_LIB_DIR)/lib$(1).a
endef

define build-bin =

$(USER_OUTPUT_DIR)/bin/$(1)/obj.o: $$(LDDEPS) uapi lib_headers libs FORCE
	$(Q)$(MAKE) -C $(USER_BIN_SOURCE_DIR)/$(1) -f $(MK_SCRIPTS_DIR)/userbuild.mk obj

bins: $$(SYSROOT_BIN_DIR)/$(1)
$$(SYSROOT_BIN_DIR)/$(1): $$(USER_OUTPUT_DIR)/bin/$(1)/obj.o $$(foreach lib,$$(USER_LIB_NAMES),$$(SYSROOT_LIB_DIR)/lib$$(lib).a)
	$$(call qinfo, $$(ULD_MSG), $$(COLOR_BRIGHT)$$(call rel-dir, $$@, $$(OUTPUT_DIR)))$$(COLOR_NORMAL)
	$$(Q)$$(USER_LD) $$(USER_LDFLAGS) $$(LDFLAGS) \
		$$(USER_OUTPUT_DIR)/bin/$(1)/obj.o -o $$(SYSROOT_BIN_DIR)/$(1) -lcrt -lc

endef

$(foreach lib,$(USER_LIB_NAMES),$(eval $(call build-lib,$(lib))))
$(foreach bin,$(USER_BIN_NAMES),$(eval $(call build-bin,$(bin))))

lib_headers: FORCE
libs: FORCE
bins: FORCE
user: libs bins FORCE

