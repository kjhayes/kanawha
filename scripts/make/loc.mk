
SLOCCOUNT ?= $(shell which sloccount)

ifneq ($(SLOCCOUNT),)
loc: FORCE
	$(Q)$(SLOCCOUNT) \
		$(ROOT_DIR)/kernel \
		$(ROOT_DIR)/include \
		$(ROOT_DIR)/drivers \
		$(ROOT_DIR)/user
else
loc: FORCE
	$(Q)find $(ROOT_DIR) -name "*.[ch]" | xargs wc -l
endif

