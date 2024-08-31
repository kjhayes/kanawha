
CRT_OBJS += \
    start.o \
	syscall.o

CRT_OUTPUT_DIR := $(OUTPUT_DIR)/crt
CRT_OUTPUT_OBJS := $(addprefix $(CRT_OUTPUT_DIR)/, $(CRT_OBJS))

$(shell mkdir -p $(CRT_OUTPUT_DIR))

crt0: $(OUTPUT_DIR)/crt0.o
$(OUTPUT_DIR)/crt0.o: $(CRT_OUTPUT_OBJS)
	$(LD) $(LDFLAGS) -r $(LINK_DIR)/crt0.ld $^ -o $@

