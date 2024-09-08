
CC := clang
CPP := cpp
LD := ld.lld
AS := clang

ifdef CONFIG_X64
AFLAGS += -mllvm -asm-macro-max-nesting-depth=1024
endif

OBJCOPY := llvm-objcopy
OBJDUMP := llvm-objdump

COMMON_FLAGS += -fno-omit-frame-pointer

