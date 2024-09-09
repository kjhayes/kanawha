
SH_OBJS := \
    main.o

SH_OUTPUT_DIR := $(OUTPUT_DIR)/sh
SH_OUTPUT_OBJS := $(addprefix $(SH_OUTPUT_DIR)/, $(SH_OBJS))

$(shell mkdir -p $(SH_OUTPUT_DIR))

sh: $(SH_OUTPUT_DIR)/sh
$(SH_OUTPUT_DIR)/sh: $(SH_OUTPUT_OBJS) $(OUTPUT_DIR)/crt0.o
	$(LD) $(LDFLAGS) $(LINK_DIR)/crt0.ld $^ -o $@

