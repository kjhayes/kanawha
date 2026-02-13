
default:
	@

-include $(MK_SCRIPTS_DIR)/include.mk

USER_COMMON_FLAGS += \
	-I$(UAPI_DIR) \
	-nostdlib \

CUR_SOURCE_DIR := $(shell pwd)/

-include $(CUR_SOURCE_DIR)/Makefile

define build-lib =
userlibs: $(OUTPUT_DIR)/$(1)
$(OUTPUT_DIR)/$(1): $(AUTOCONF) FORCE
	$(Q)$(MAKE) -C $(CUR_SOURCE_DIR)/$(1) -f $(MK_SCRIPTS_DIR)/userbuild.mk obj
endef

$(foreach lib,$(libs),$(eval $(call build-lib,$(lib))))

userlibs: FORCE

default: userlibs FORCE

