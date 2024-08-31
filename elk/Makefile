
default:
	@

KANAWHA_ROOT := ../
KANAWHA_INCLUDE_DIR := $(KANAWHA_ROOT)/include

ROOT_DIR := $(shell pwd)
SRC_DIR := $(ROOT_DIR)/src
OUTPUT_DIR := $(ROOT_DIR)/build
LINK_DIR := $(ROOT_DIR)/link
INCLUDE_DIR := $(ROOT_DIR)/include

AS := clang
CC := clang
LD := ld.lld
OBJCOPY := llvm-objcopy
OBJDUMP := llvm-objdump

CFLAGS +=
AFLAGS +=
COMMON_FLAGS += \
    -nostdlib \
	-static \
	-I$(KANAWHA_INCLUDE_DIR) \
	-I$(INCLUDE_DIR)


CRT_SRC_DIR := $(SRC_DIR)/c
include $(CRT_SRC_DIR)/Makefile

INIT_SRC_DIR := $(SRC_DIR)/init
include $(INIT_SRC_DIR)/Makefile

$(shell mkdir -p $(OUTPUT_DIR))

$(OUTPUT_DIR)/%.o: $(SRC_DIR)/%.S
	$(AS) -c $(AFLAGS) $(COMMON_FLAGS) $< -o $@

$(OUTPUT_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) -c $(CFLAGS) $(COMMON_FLAGS) $< -o $@

FORCE:

clean: FORCE
	find $(OUTPUT_DIR) -name "*.o" -delete
	find $(OUTPUT_DIR) -name "*.bin" -delete

.PRECIOUS: $(OUTPUT_DIR)/%.o

