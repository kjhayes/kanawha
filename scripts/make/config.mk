ifndef __KANAWHA_CONFIG_H__
define __KANAWHA_CONFIG_H__
endef

DOT_CONFIG ?= $(ROOT_DIR)/.config
AUTOCONF ?= $(OUTPUT_DIR)/autoconf.h

#defconfig: FORCE
#	$(Q)$(PYTHON) -m defconfig $(SETUPS_DIR)/$(ARCH)/$@
#
#%defconfig: FORCE
#	$(Q)$(PYTHON) -m defconfig $(SETUPS_DIR)/$@

menuconfig: FORCE
	$(Q)$(PYTHON) -m menuconfig

$(AUTOCONF): $(OUTPUT_DIR) $(DOT_CONFIG)
	$(Q)$(PYTHON) -m genconfig --header-path $@

export
-include $(DOT_CONFIG)

.PHONY: menuconfig defconfig

endif
