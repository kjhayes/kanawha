
#include <mb2/header.h>

struct mb2_header_data {
    struct mb2_header header;

    struct mb2_tag_header terminator_tag;
}; 

__attribute__((used))
__attribute__((section(".hdrs.multiboot2")))
static struct mb2_header_data mb2_header_data = {
    .header = {
        .magic = MB2_HEADER_MAGIC,
        .arch = MB2_HEADER_ARCH_PROT_I386,
        .hdr_length = sizeof(struct mb2_header_data),
        .checksum = (uint32_t)-(
                MB2_HEADER_MAGIC + 
                MB2_HEADER_ARCH_PROT_I386 +
                sizeof(struct mb2_header_data)),
    },

    .terminator_tag = {
        .type = 0,
        .flags = 0,
        .size = 8,
    },
};

