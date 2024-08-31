
default:
	@

KANAWHA_ROOT := ../
KANAWHA_INCLUDE_DIR := $(KANAWHA_ROOT)/include

ROOT_DIR := $(shell pwd)
SRC_DIR := $(ROOT_DIR)/src
OUTPUT_DIR := $(ROOT_DIR)/build
LINK_DIR := $(ROOT_DIR)/link
INCLUDE_DIR := $(ROOT_DIR)/include

$(shell mkdir -p $(OUTPUT_DIR))

AS := clang
CC := clang
LD := ld.lld
OBJCOPY := llvm-objcopy
OBJDUMP := llvm-objdump

CFLAGS +=
AFLAGS +=
COMMON_FLAGS += -nostdlib -static -I$(KANAWHA_INCLUDE_DIR) -I$(INCLUDE_DIR) -g

OBJS := main.o start.o syscall.o
OUTPUT_OBJS := $(addprefix $(OUTPUT_DIR)/, $(OBJS))

$(OUTPUT_DIR)/%.o: $(SRC_DIR)/%.S
	$(AS) -c $(AFLAGS) $(COMMON_FLAGS) $< -o $@

$(OUTPUT_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) -c $(CFLAGS) $(COMMON_FLAGS) $< -o $@

init.bin: $(OUTPUT_DIR)/init.bin

init: $(OUTPUT_DIR)/init
$(OUTPUT_DIR)/init: $(OUTPUT_OBJS)
	$(LD) $(LDFLAGS) $(LINK_DIR)/user.ld $^ -o $@

$(OUTPUT_DIR)/%.bin: $(OUTPUT_DIR)/%.o
	$(OBJCOPY) -O binary $< $@

FORCE:

clean: FORCE
	find $(OUTPUT_DIR) -name "*.o" -delete
	find $(OUTPUT_DIR) -name "*.bin" -delete

default: $(OUTPUT_DIR)/init

.PRECIOUS: $(OUTPUT_DIR)/%.o

