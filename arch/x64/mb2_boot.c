
#include <kanawha/attribute.h>
#include <mb2/header.h>

struct __packed mb2_header_data
{
    struct mb2_header header;

#ifdef CONFIG_MULTIBOOT2_FRAMEBUFFER
    struct __packed
    {
        struct mb2_tag_header hdr;
        uint32_t width;
        uint32_t height;
        uint32_t depth;
        uint32_t __padding;
    } framebuffer;
#endif

    struct mb2_tag_header terminator_tag;
};

__attribute__((used)) __attribute__((section(
    ".hdrs.multiboot2"))) static struct mb2_header_data mb2_header_data = {
    .header =
        {
            .magic = MB2_HEADER_MAGIC,
            .arch = MB2_HEADER_ARCH_PROT_I386,
            .hdr_length = sizeof(struct mb2_header_data),
            .checksum =
                (uint32_t)-(MB2_HEADER_MAGIC + MB2_HEADER_ARCH_PROT_I386 +
                            sizeof(struct mb2_header_data)),
        },

#ifdef CONFIG_MULTIBOOT2_FRAMEBUFFER
    .framebuffer =
        {
            .hdr =
                {
                    .type = 5,
                    .flags = 0,
                    .size = 20,
                },
            .width = 0,
            .height = 0,
            .depth = 0,
        },
#endif

    .terminator_tag =
        {
            .type = 0,
            .flags = 0,
            .size = 8,
        },
};
