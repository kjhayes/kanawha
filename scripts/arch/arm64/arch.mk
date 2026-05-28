
KERNEL_COMMON_FLAGS += -mno-outline-atomics \
					   -mgeneral-regs-only

DEFAULT_BUILD_RULE ?= $(OUTPUT_DIR)/kanawha.o

KERNEL_OBJDUMPFLAGS += \
	-j .boot.text \
	-j .text

