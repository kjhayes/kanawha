
MOUNT_OBJS := \
    main.o

MOUNT_OUTPUT_DIR := $(OUTPUT_DIR)/mount
MOUNT_OUTPUT_OBJS := $(addprefix $(MOUNT_OUTPUT_DIR)/, $(MOUNT_OBJS))

$(shell mkdir -p $(MOUNT_OUTPUT_DIR))

mount: $(MOUNT_OUTPUT_DIR)/mount
$(MOUNT_OUTPUT_DIR)/mount: $(MOUNT_OUTPUT_OBJS) $(OUTPUT_DIR)/crt0.o
	$(LD) $(LDFLAGS) $(LINK_DIR)/crt0.ld $^ -o $@

