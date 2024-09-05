
LIBC_OBJS := \


LIBC_OUTPUT_DIR := $(OUTPUT_DIR)/libc
LIBC_OUTPUT_OBJS := $(addprefix $(LIBC_OUTPUT_DIR)/, $(LIBC_OBJS))

$(shell mkdir -p $(LIBC_OUTPUT_DIR))

libc.o: $(OUTPUT_DIR)/libc.o
$(OUTPUT_DIR)/libc.o: $(LIBC_OUTPUT_OBJS)
	$(LD) $(LDFLAGS) $(LINK_DIR)/crt0.ld $^ -o $@

