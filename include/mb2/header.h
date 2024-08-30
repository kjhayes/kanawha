#ifndef __KANAWHA_MB2_HEADER_H__
#define __KANAWHA_MB2_HEADER_H__

#include <kanawha/stdint.h>

#define MB2_HEADER_MAGIC 0xE85250D6

#define MB2_HEADER_ARCH_PROT_I386 0
#define MB2_HEADER_ARCH_MIPS_32   4

struct mb2_header {
    uint32_t magic;
    uint32_t arch;
    uint32_t hdr_length;
    uint32_t checksum;
};

struct mb2_tag_header {
    uint16_t type;
    uint16_t flags;
    uint32_t size;
};

#define MB2_TAG_TYPE_ENTRY_ADDR 3
struct mb2_entry_addr_tag {
    struct mb2_tag_header header;
    uint32_t entry_addr;
};

#endif
