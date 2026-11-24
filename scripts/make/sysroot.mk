
SYSROOT_DIR := $(OUTPUT_DIR)/sysroot
SYSROOT_INCLUDE_DIR := $(SYSROOT_DIR)/include
SYSROOT_LIB_DIR := $(SYSROOT_DIR)/lib
SYSROOT_BIN_DIR := $(SYSROOT_DIR)/bin

$(shell mkdir -p $(SYSROOT_DIR))
$(shell mkdir -p $(SYSROOT_INCLUDE_DIR))
$(shell mkdir -p $(SYSROOT_LIB_DIR))
$(shell mkdir -p $(SYSROOT_BIN_DIR))

# UAPI

SYSROOT_UAPI_INCLUDE_DIR := $(SYSROOT_INCLUDE_DIR)/kanawha/
$(shell mkdir -p $(SYSROOT_UAPI_INCLUDE_DIR))

SOURCE_UAPI_HEADERS := $(wildcard $(INCLUDE_DIR)/kanawha/uapi/*.h)
SYSROOT_UAPI_HEADERS := $(SOURCE_UAPI_HEADERS:$(INCLUDE_DIR)/kanawha/uapi/%=$(SYSROOT_UAPI_INCLUDE_DIR)/%)

$(SYSROOT_UAPI_HEADERS) &: $(SOURCE_UAPI_HEADERS)
	$(call qinfo, $(CP_MSG), $(call rel-dir, $(SYSROOT_UAPI_INCLUDE_DIR), $(OUTPUT_DIR))/*.h)
	$(Q)cp -RT $(INCLUDE_DIR)/kanawha/uapi $(SYSROOT_UAPI_INCLUDE_DIR)

uapi: $(SYSROOT_UAPI_HEADERS)

uapi_config: $(SYSROOT_UAPI_INCLUDE_DIR)/kanawha-config.h
$(SYSROOT_UAPI_INCLUDE_DIR)/kanawha-config.h: $(KERNEL_AUTOCONF)
	$(call qinfo, $(CP_MSG), $(call rel-dir, $@, $(OUTPUT_DIR)))
	$(Q)cp $(KERNEL_AUTOCONF) $@
uapi: uapi_config

# User Libraries

# User Binaries

