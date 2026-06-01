
KERNEL_COMMON_FLAGS += -mno-outline-atomics \
					   -mgeneral-regs-only
USER_COMMON_FLAGS += -mno-outline-atomics

KERNEL_OBJDUMPFLAGS += \
	-j .boot.text \
	-j .text

USER_COMMON_FLAGS += \
	-D__aarch64__ \

DEFAULT_BUILD_RULE ?= $(OUTPUT_DIR)/kanawha.o
