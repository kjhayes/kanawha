ifndef __KANAWHA_CONFIG_H__
define __KANAWHA_CONFIG_H__
endef

KANAWHA_LIGHT_BLUE := \#5A6CD5
KANAWHA_DARK_BLUE := \#000080
KANAWHA_SOFT_BLUE := \#1E2F7C
KANAWHA_BLUE := \#2C40AF
KANAWHA_YELLOW := \#D2D57F

KANAWHA_LIGHT_GREY := \#B6B6B6
KANAWHA_BLACK := \#000000

KANAWHA_PRIMARY_LIGHT := $(KANAWHA_YELLOW)
KANAWHA_SECONDARY_LIGHT := $(KANAWHA_LIGHT_BLUE)

KANAWHA_PRIMARY_DARK := $(KANAWHA_BLACK)
KANAWHA_SECONDARY_DARK := $(KANAWHA_DARK_BLUE)

KANAWHA_PRIMARY_FG := $(KANAWHA_PRIMARY_LIGHT)
KANAWHA_SECONDARY_FG := $(KANAWHA_SECONDARY_LIGHT)

KANAWHA_PRIMARY_BG := $(KANAWHA_PRIMARY_DARK)
KANAWHA_SECONDARY_BG := $(KANAWHA_SECONDARY_DARK)

KANAWHA_MENUCONFIG_STYLE := "\
    frame=fg:$(KANAWHA_SECONDARY_FG),bg:$(KANAWHA_SECONDARY_BG),bold\
    body=fg:$(KANAWHA_PRIMARY_FG),bg:$(KANAWHA_PRIMARY_BG)\
    path=frame\
    separator=frame\
    list=body\
    selection=fg:$(KANAWHA_PRIMARY_BG),bg:$(KANAWHA_PRIMARY_FG),bold\
	inv-selection=fg:$(KANAWHA_PRIMARY_FG),bg:$(KANAWHA_PRIMARY_BG),bold\
    inv-list=selection\
	help=body\
	show-help=help\
    edit=body\
    jump-edit=edit\
    text=list\
	"

export MENUCONFIG_STYLE = $(KANAWHA_MENUCONFIG_STYLE)

DOT_CONFIG ?= $(ROOT_DIR)/.config
KERNEL_AUTOCONF ?= $(OUTPUT_DIR)/autoconf.h

defconfig/%: $(SETUPS_DIR)/%/defconfig FORCE
	$(Q)cp $(SETUPS_DIR)/$(*)/defconfig $(DOT_CONFIG)
defconfig/%: $(SETUPS_DIR)/%_defconfig FORCE
	$(Q)cp $(SETUPS_DIR)/$(*)_defconfig $(DOT_CONFIG)


menuconfig: FORCE
	$(Q)$(PYTHON) -m menuconfig

$(KERNEL_AUTOCONF): $(OUTPUT_DIR) $(DOT_CONFIG)
	$(Q)$(PYTHON) -m genconfig --header-path $@

export
-include $(DOT_CONFIG)

endif
