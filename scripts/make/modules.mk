
-include $(MK_SCRIPTS_DIR)/include.mk

CUR_SOURCE_DIR := $(shell pwd)/
CUR_REL_DIR := $(call rel-dir, $(CUR_SOURCE_DIR), $(ROOT_DIR))
CUR_OBJ_OUTPUT_DIR := $(OUTPUT_DIR)/$(CUR_REL_DIR)/
CUR_MOD_OUTPUT_DIR := $(MODULE_OUTPUT_DIR)/$(CUR_REL_DIR)/

include $(CUR_SOURCE_DIR)/Makefile

$(CUR_MOD_OUTPUT_DIR): FORCE
	$(Q)mkdir -p $(CUR_MOD_OUTPUT_DIR)

goal := $(MAKECMDGOALS)

# Get the list of obj-m we are building
mods := $($(goal)-m)
prefixed-mods := $(strip $(addprefix $(CUR_MOD_OUTPUT_DIR), $(mods)))
mod-objs := $(filter %.o, $(prefixed-mods))
mod-kobjs := $(mod-objs:.o=.ko)

# Figure out if any of our obj-m are directories (so we can error out)
mod-dirs := $(filter-out %.o, $(prefixed-mod))

# We need to traverse the obj-y directories looking for more modules
obj-in := $($(goal)-y)
prefixed-obj-in := $(strip $(addprefix $(CUR_SOURCE_DIR), $(obj-in)))
obj-in-dirs := $(filter-out %.o, $(prefixed-obj-in))
obj-in-dir-mod-rules := $(addsuffix modules, $(obj-in-dirs))

ifneq ($(strip $(mod-dirs)),)
$(error "Included a directory in module list! Module: $(goal)-m Directories: $(mod-dirs)")
endif

define build_mod_obj_rule =
$(1): FORCE | $(CUR_MOD_OUTPUT_DIR)
	$$(Q)$$(MAKE) -C $$(CUR_SOURCE_DIR) -f $$(MK_SCRIPTS_DIR)/build.mk $$(CUR_OBJ_OUTPUT_DIR)$$(notdir $$@)
	$$(Q)cp $$(CUR_OBJ_OUTPUT_DIR)$$(notdir $$@) $$@
endef

%.ko: %.o $(LDDEPS)
	$(call qinfo, LD, $(call rel-dir, $@, $(OUTPUT_DIR)))
	$(Q)$(LD) $(LDFLAGS) -r $< -o $@

$(foreach mod,$(mod-objs),$(eval $(call build_mod_obj_rule,$(mod))))

%/modules: FORCE | $(CUR_MOD_OUTPUT_DIR)
	$(Q)$(MAKE) -C $* -f $(MK_SCRIPTS_DIR)/modules.mk $(goal)

$(goal): $(mod-kobjs) $(obj-in-dir-mod-rules) FORCE

