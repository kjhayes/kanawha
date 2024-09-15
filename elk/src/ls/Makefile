
LS_OBJS := \
    main.o

LS_OUTPUT_DIR := $(OUTPUT_DIR)/ls
LS_OUTPUT_OBJS := $(addprefix $(LS_OUTPUT_DIR)/, $(LS_OBJS))

$(shell mkdir -p $(LS_OUTPUT_DIR))

ls: $(LS_OUTPUT_DIR)/ls
$(LS_OUTPUT_DIR)/ls: $(LS_OUTPUT_OBJS) $(OUTPUT_DIR)/crt0.o
	$(LD) $(LDFLAGS) $(LINK_DIR)/crt0.ld $^ -o $@

