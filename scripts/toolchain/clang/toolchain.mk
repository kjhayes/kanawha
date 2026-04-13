
ifdef CONFIG_X64
KERNEL_AFLAGS += -mllvm -asm-macro-max-nesting-depth=1024
KERNEL_COMMON_FLAGS += -fno-omit-frame-pointer
USER_CROSS_COMPILE_PREFIX := x86_64-kanawha-
endif
ifdef CONFIG_RISCV64
KERNEL_AFLAGS += -mllvm -asm-macro-max-nesting-depth=1024
LLVM_FLAGS += -target riscv64
USER_CROSS_COMPILE_PREFIX := riscv64-unknown-elf-
endif
ifdef CONFIG_ARM64
KERNEL_AFLAGS += -mllvm -asm-macro-max-nesting-depth=1024
LLVM_FLAGS += -target aarch64
USER_CROSS_COMPILE_PREFIX := aarch64-linux-gnu-
endif


# Clang-18 doesn't respect -mcmodel=large for assembly files
CC  := clang-17 $(LLVM_FLAGS)
CPP := clang -E -x c $(LLVM_FLAGS)
LD  := ld.lld-17
AS  := clang-17 $(LLVM_FLAGS)

OBJCOPY := llvm-objcopy
OBJDUMP := llvm-objdump

KERNEL_CC      := $(CC)
KERNEL_CPP     := $(CPP)
KERNEL_LD      := $(LD)
KERNEL_AS      := $(AS)
KERNEL_OBJCOPY := $(OBJCOPY)
KERNEL_OBJDUMP := $(OBJDUMP)

# We do not have a version of clang building
# for kanawha, so we still use GCC for userspace
USER_CC      := $(USER_CROSS_COMPILE_PREFIX)gcc
USER_CPP     := $(USER_CROSS_COMPILE_PREFIX)gcc -E
USER_LD      := $(USER_CROSS_COMPILE_PREFIX)ld
USER_AS      := $(USER_CROSS_COMPILE_PREFIX)gcc
USER_OBJCOPY := $(USER_CROSS_COMPILE_PREFIX)objcopy
USER_OBJDUMP := $(USER_CROSS_COMPILE_PREFIX)objdump
