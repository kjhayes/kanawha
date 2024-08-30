
-include $(MK_SCRIPTS_DIR)/include.mk

CUR_SOURCE_DIR := $(shell pwd)/
CUR_REL_DIR := $(call rel-dir, $(CUR_SOURCE_DIR), $(ROOT_DIR))
CUR_OBJ_OUTPUT_DIR := $(OUTPUT_DIR)/$(CUR_REL_DIR)/

-include $(CUR_SOURCE_DIR)/Makefile

goal := $(MAKECMDGOALS)
goal-suffix := $(strip $(suffix $(goal)))

define include_dep_file =
-include $(1)
endef

ifeq ($(goal-suffix),) # This is a "pure" goal (sources are $($(goal)-y))

obj-in := $($(goal)-y)
prefixed-obj-in := $(strip $(addprefix $(CUR_OBJ_OUTPUT_DIR), $(obj-in)))
obj-in-dirs := $(filter-out %.o, $(prefixed-obj-in))
obj-in-objs := $(filter %.o, $(prefixed-obj-in))
obj-in-deps := $(obj-in-objs:%.o=%.d)
final-obj-in := $(obj-in-objs) $(addsuffix $(goal).o, $(obj-in-dirs))

$(foreach DEP_FILE,$(obj-in-deps),$(eval $(call include_dep_file,$(DEP_FILE))))

# sub-directory -> sub-dir/.o rule
$(CUR_OBJ_OUTPUT_DIR)%/$(goal).o: FORCE
	$(Q)$(MAKE) -C $(CUR_SOURCE_DIR)$* -f $(MK_SCRIPTS_DIR)/build.mk $(goal) 

$(goal): $(CUR_OBJ_OUTPUT_DIR)$(goal).o
$(CUR_OBJ_OUTPUT_DIR)$(goal).o: $(final-obj-in) $(LDDEPS) | $(CUR_OBJ_OUTPUT_DIR)
	$(call qinfo, LD, $(call rel-dir, $@, $(OUTPUT_DIR)))
	$(Q)$(LD) $(LDFLAGS) -r $(final-obj-in) -o $@

else
# If we aren't a pure-goal, try to include our dep-file
ifeq ($(goal-suffix),.o)
$(eval $(call include_dep_file, $(goal:.o=.d)))
endif
endif

# Generic build rules, doesn't matter if we are a pure-goal or not

$(CUR_OBJ_OUTPUT_DIR): FORCE
	$(Q)mkdir -p $@

$(CUR_OBJ_OUTPUT_DIR)%.d: $(CUR_SOURCE_DIR)%.c $(CDEPS) $(COMMON_DEPS) | $(CUR_OBJ_OUTPUT_DIR)
	$(call qinfo, CPP, $(call rel-dir, $@, $(OUTPUT_DIR)))
	$(Q)$(CPP) $(CFLAGS) $(COMMON_FLAGS) -MM -MG $< -MT $(@:%.d=%.o) -o $@

$(CUR_OBJ_OUTPUT_DIR)%.d: $(CUR_SOURCE_DIR)%.S $(CDEPS) $(COMMON_DEPS) | $(CUR_OBJ_OUTPUT_DIR)
	$(call qinfo, CPP, $(call rel-dir, $@, $(OUTPUT_DIR)))
	$(Q)$(CPP) $(CFLAGS) $(COMMON_FLAGS) -MM -MG $< -MT $(@:%.d=%.o) -o $@

# .c/.S -> .o build rules
$(CUR_OBJ_OUTPUT_DIR)%.o: $(CUR_SOURCE_DIR)%.c $(CDEPS) $(COMMON_DEPS) | $(CUR_OBJ_OUTPUT_DIR)
	$(call qinfo, CC, $(call rel-dir, $@, $(OUTPUT_DIR)))
	$(Q)$(CC) $(CFLAGS) $(COMMON_FLAGS) -c $< -o $@

$(CUR_OBJ_OUTPUT_DIR)%.o: $(CUR_SOURCE_DIR)%.S $(ADEPS) $(COMMON_DEPS) | $(CUR_OBJ_OUTPUT_DIR)
	$(call qinfo, AS, $(call rel-dir, $@, $(OUTPUT_DIR)))
	$(Q)$(AS) $(AFLAGS) $(COMMON_FLAGS) -c $< -o $@

$(CUR_OBJ_OUTPUT_DIR)%.o: FORCE
	$(Q)$(MAKE) -C $(CUR_SOURCE_DIR) -f $(MK_SCRIPTS_DIR)/build.mk $(basename $(notdir $@))

