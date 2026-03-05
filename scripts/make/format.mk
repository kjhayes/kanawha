
# I generally don't like forcing formatting, but something
# keeps messing with my spacing/indentation and I'd like to
# be able to drop the heavy hammer and force all of my C
# code to use spaces instead of tabs...

format: FORCE
	$(call qinfo, FORMAT, $(call rel-dir, $(KERNEL_DIR), $(ROOT_DIR)))
	$(Q)find $(KERNEL_DIR) -name "*.[ch]" | xargs clang-format -i
	$(call qinfo, FORMAT, $(call rel-dir, $(ARCH_ROOT_DIR), $(ROOT_DIR)))
	$(Q)find $(ARCH_ROOT_DIR) -name "*.[ch]" | xargs clang-format -i
	$(call qinfo, FORMAT, $(call rel-dir, $(DRIVER_DIR), $(ROOT_DIR)))
	$(Q)find $(DRIVER_DIR) -name "*.[ch]" | xargs clang-format -i
	$(call qinfo, FORMAT, $(call rel-dir, $(USER_DIR), $(ROOT_DIR)))
	$(Q)find $(USER_DIR) -name "*.[ch]" | xargs clang-format -i
	$(call qinfo, FORMAT, $(call rel-dir, $(INCLUDE_DIR), $(ROOT_DIR)))
	$(Q)find $(INCLUDE_DIR) -name "*.[ch]" | xargs clang-format -i

