
# Clang-18 doesn't respect -mcmodel=large for assembly files
CC := clang-17
CPP := cpp
LD := ld.lld-17
AS := clang-17

ifdef CONFIG_X64
AFLAGS += -mllvm -asm-macro-max-nesting-depth=1024
endif

OBJCOPY := llvm-objcopy
OBJDUMP := llvm-objdump

COMMON_FLAGS += -fno-omit-frame-pointer

