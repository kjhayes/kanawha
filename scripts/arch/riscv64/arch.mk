
KERNEL_COMMON_FLAGS += \
	-mcmodel=medany \
	-mno-relax \

# GCC Really likes to try putting jump tables into the boot code
# for RISC-V (and then put then in a section which is too far away...)
KERNEL_COMMON_FLAGS += -fno-jump-tables
USER_COMMON_FLAGS += -march=rv64g -mabi=lp64 \
					 -D__riscv64__

DEFAULT_BUILD_RULE ?= binary

