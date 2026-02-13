ifndef __KANAWHA_CONFIG_H__
define __KANAWHA_CONFIG_H__
endef

DOT_CONFIG ?= $(ROOT_DIR)/.config
KERNEL_AUTOCONF ?= $(OUTPUT_DIR)/autoconf.h

%/defconfig: $(SETUPS_DIR)/%/defconfig FORCE
	$(Q)cp $(SETUPS_DIR)/$@ $(DOT_CONFIG)

menuconfig: FORCE
	$(Q)$(PYTHON) -m menuconfig

$(KERNEL_AUTOCONF): $(OUTPUT_DIR) $(DOT_CONFIG)
	$(Q)$(PYTHON) -m genconfig --header-path $@

export
-include $(DOT_CONFIG)

endif
