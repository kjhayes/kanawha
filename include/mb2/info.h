#ifndef __KANAWHA__MULTIBOOT2_INFO_H__
#define __KANAWHA__MULTIBOOT2_INFO_H__

#include <kanawha/stdint.h>
#include <kanawha/section.h>

struct mb2_info_header {
    uint32_t total_size;
    uint32_t __resv0;
} __attribute__((packed));

struct mb2_info {
    struct mb2_info_header hdr;
    uint8_t raw_tags[];
} __attribute__((packed));

struct mb2_info_tag_header {
    uint32_t type;
    uint32_t size;
} __attribute__((packed));

#define MB2_INFO_TAG_TYPE_MODULE 3
#define MB2_INFO_TAG_TYPE_BASIC_MEM_INFO 4
#define MB2_INFO_TAG_TYPE_MEM_MAP 6

struct mb2_info_tag {
    struct mb2_info_tag_header hdr;
    union {
        struct {
            uint32_t mem_lower;
            uint32_t mem_upper;
        } basic_mem_info;
        struct {
            uint32_t entry_size;
            uint32_t entry_version;
            struct mb2_info_tag_mem_map_entry {
                uint64_t base_addr;
                uint64_t length;
                uint32_t type;
                uint32_t reserved;
            } entries[];
        } mem_map;
        struct {
            uint32_t mod_start;
            uint32_t mod_end;
            uint8_t utf8_str[];
        } module;
    };
} __attribute__((packed));

typedef void(mb2_info_tag_handler_f)(struct mb2_info *info, struct mb2_info_tag *tag, void *private);

int mb2_info_for_each_tag(struct mb2_info *info, mb2_info_tag_handler_f *handler, void *private);

extern __boot_data struct mb2_info *boot_mb2_info_ptr;

#endif
