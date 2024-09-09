
INIT_OBJS := \
    main.o \
	path.o

INIT_OUTPUT_DIR := $(OUTPUT_DIR)/init
INIT_OUTPUT_OBJS := $(addprefix $(INIT_OUTPUT_DIR)/, $(INIT_OBJS))

$(shell mkdir -p $(INIT_OUTPUT_DIR))

init: $(INIT_OUTPUT_DIR)/init
$(INIT_OUTPUT_DIR)/init: $(INIT_OUTPUT_OBJS) $(OUTPUT_DIR)/crt0.o
	$(LD) $(LDFLAGS) $(LINK_DIR)/crt0.ld $^ -o $@

