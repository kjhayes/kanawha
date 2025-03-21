
SYSROOT_DIR := $(OUTPUT_DIR)/sysroot
SYSROOT_LIB_DIR := $(SYSROOT_DIR)/usr/lib
SYSROOT_INCLUDE_DIR := $(SYSROOT_DIR)/usr/include

sysroot: $(SYSROOT_DIR)
$(SYSROOT_DIR): FORCE
	$(Q)mkdir -p $@
	$(Q)mkdir -p $@/usr/
	$(Q)mkdir -p $(SYSROOT_LIB_DIR)
	$(Q)mkdir -p $(SYSROOT_INCLUDE_DIR)
	$(Q)cp -RT $(LIBC_INCLUDE_DIR) $(SYSROOT_INCLUDE_DIR)
	$(Q)cp -RT $(INCLUDE_DIR)/posix $(SYSROOT_INCLUDE_DIR)
	$(Q)cp -r $(INCLUDE_DIR)/kanawha $(SYSROOT_INCLUDE_DIR)
	$(Q)cp -RT $(CONFIG_KANAWHA_INCLUDE_PATH)/kanawha/uapi $(SYSROOT_INCLUDE_DIR)/kanawha
	$(Q)cp $(OUTPUT_DIR)/crt0.o $(SYSROOT_LIB_DIR)
	$(Q)cp $(OUTPUT_DIR)/crt1.o $(SYSROOT_LIB_DIR)
	$(Q)cp $(OUTPUT_DIR)/crti.o $(SYSROOT_LIB_DIR)
	$(Q)cp $(OUTPUT_DIR)/crtn.o $(SYSROOT_LIB_DIR)
	$(Q)cp $(OUTPUT_DIR)/libc.a $(SYSROOT_LIB_DIR)
	$(Q)cp $(OUTPUT_DIR)/libkfb.a $(SYSROOT_LIB_DIR)

