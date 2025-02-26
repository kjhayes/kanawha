
ifdef CONFIG_X64
AFLAGS += -mllvm -asm-macro-max-nesting-depth=1024
COMMON_FLAGS += -fno-omit-frame-pointer
endif
ifdef CONFIG_RISCV64
AFLAGS += -mllvm -asm-macro-max-nesting-depth=1024
LLVM_FLAGS += -target riscv64
endif

# Clang-18 doesn't respect -mcmodel=large for assembly files
CC := clang-17 $(LLVM_FLAGS)
CPP := clang -E -x c $(LLVM_FLAGS)
LD := ld.lld-17
AS := clang-17 $(LLVM_FLAGS)

OBJCOPY := llvm-objcopy $(LLVM_FLAGS)
OBJDUMP := llvm-objdump $(LLVM_FLAGS)

