#ifndef __KANAWHA__MULTIBOOT2_INFO_H__
#define __KANAWHA__MULTIBOOT2_INFO_H__

#include <kanawha/attribute.h>
#include <kanawha/section.h>
#include <kanawha/types.h>

struct __packed mb2_info_header
{
    uint32_t total_size;
    uint32_t __resv0;
};

struct __packed mb2_info
{
    struct mb2_info_header hdr;
    uint8_t raw_tags[];
};

struct __packed mb2_info_tag_header
{
    uint32_t type;
    uint32_t size;
};

#define MB2_INFO_TAG_TYPE_MODULE 3
#define MB2_INFO_TAG_TYPE_BASIC_MEM_INFO 4
#define MB2_INFO_TAG_TYPE_MEM_MAP 6
#define MB2_INFO_TAG_TYPE_FRAMEBUFFER_INFO 8

struct __packed mb2_info_tag
{
    struct mb2_info_tag_header hdr;
    union
    {
        struct __packed
        {
            uint32_t mem_lower;
            uint32_t mem_upper;
        } basic_mem_info;
        struct __packed
        {
            uint32_t entry_size;
            uint32_t entry_version;
            struct mb2_info_tag_mem_map_entry
            {
                uint64_t base_addr;
                uint64_t length;
                uint32_t type;
                uint32_t reserved;
            } entries[];
        } mem_map;
        struct __packed
        {
            uint32_t mod_start;
            uint32_t mod_end;
            uint8_t utf8_str[];
        } module;
        struct __packed
        {
            uint64_t phys_addr;
            uint32_t pitch;
            uint32_t width;
            uint32_t height;
            uint8_t bpp;
            uint8_t type;
            uint8_t __resv;
            uint8_t color_data[];
        } fb_info;
    };
};

typedef void(mb2_info_tag_handler_f)(struct mb2_info *info,
                                     struct mb2_info_tag *tag,
                                     void *private);

int
mb2_info_for_each_tag(struct mb2_info *info,
                      mb2_info_tag_handler_f *handler,
                      void *private);

extern __boot_data struct mb2_info *boot_mb2_info_ptr;

#endif
