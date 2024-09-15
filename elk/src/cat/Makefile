
CAT_OBJS := \
    main.o

CAT_OUTPUT_DIR := $(OUTPUT_DIR)/cat
CAT_OUTPUT_OBJS := $(addprefix $(CAT_OUTPUT_DIR)/, $(CAT_OBJS))

$(shell mkdir -p $(CAT_OUTPUT_DIR))

cat: $(CAT_OUTPUT_DIR)/cat
$(CAT_OUTPUT_DIR)/cat: $(CAT_OUTPUT_OBJS) $(OUTPUT_DIR)/crt0.o
	$(LD) $(LDFLAGS) $(LINK_DIR)/crt0.ld $^ -o $@

