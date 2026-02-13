
install: FORCE
	$(Q)mkdir -p $(SYSROOT_LIB_DIR)
	$(Q)mkdir -p $(SYSROOT_INCLUDE_DIR)
	$(Q)cp -RT $(LIBC_INCLUDE_DIR) $(SYSROOT_INCLUDE_DIR)
	$(Q)cp -RT $(INCLUDE_DIR)/posix $(SYSROOT_INCLUDE_DIR)
	$(Q)cp -RT $(INCLUDE_DIR)/dl $(SYSROOT_INCLUDE_DIR)
	$(Q)cp -RT $(INCLUDE_DIR)/libkfb $(SYSROOT_INCLUDE_DIR)
	$(Q)cp -r $(INCLUDE_DIR)/kanawha $(SYSROOT_INCLUDE_DIR)
	$(Q)cp -RT $(CONFIG_KANAWHA_INCLUDE_PATH)/kanawha/uapi $(SYSROOT_INCLUDE_DIR)/kanawha
	$(Q)cp -RT $(CONFIG_KANAWHA_INCLUDE_PATH)/kanawha/uapi $(SYSROOT_INCLUDE_DIR)/kanawha/uapi
	$(Q)cp $(OUTPUT_DIR)/crt0.o $(SYSROOT_LIB_DIR)
	$(Q)cp $(OUTPUT_DIR)/crt1.o $(SYSROOT_LIB_DIR)
	$(Q)cp $(OUTPUT_DIR)/crti.o $(SYSROOT_LIB_DIR)
	$(Q)cp $(OUTPUT_DIR)/crtn.o $(SYSROOT_LIB_DIR)
	$(Q)cp $(OUTPUT_DIR)/libc.a $(SYSROOT_LIB_DIR)
	$(Q)cp $(OUTPUT_DIR)/libdl.a $(SYSROOT_LIB_DIR)
	$(Q)cp $(OUTPUT_DIR)/libkfb.a $(SYSROOT_LIB_DIR)

