
crt0-obj-y += \
	bss.o \
	argv.o \
	stdstreams.o \
	signal.o \
	zero_page.o \
	environ.o \

crt0-obj-$(CONFIG_X64) += x64_start.o
crt0-obj-$(CONFIG_RISCV64) += riscv64_start.o
