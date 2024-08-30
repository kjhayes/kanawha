
#include <mb2/info.h>
#include <kanawha/mem_flags.h>
#include <kanawha/printk.h>
#include <kanawha/errno.h>
#include <kanawha/init.h>

struct mb2_memory_info {
    int basic_info_found;
    struct mb2_info_tag *basic_info_tag;
    int mem_map_found;
    struct mb2_info_tag *mem_map_tag;
};

struct mb2_mem_map_entry {
    uint64_t base;
    uint64_t length;
    uint32_t type;
    uint32_t reserved;
} __attribute__((packed));

static void
mb2_memory_info_handler(
        struct mb2_info *info,
        struct mb2_info_tag *tag,
        void *state)
{
    struct mb2_memory_info *mem_info = (struct mb2_memory_info*)state;

    switch(tag->hdr.type) 
    {
        case MB2_INFO_TAG_TYPE_BASIC_MEM_INFO:
            mem_info->basic_info_found = 1;
            mem_info->basic_info_tag = tag;
            break;
        case MB2_INFO_TAG_TYPE_MEM_MAP:
            mem_info->mem_map_found = 1;
            mem_info->mem_map_tag = tag;
            break;
    }
}

static int
mb2_handle_mem_flags(struct mb2_info_tag *tag, struct mem_flags *map) 
{
    int res;
    for(size_t off = 16; off < tag->hdr.size; off += tag->mem_map.entry_size) {
        struct mb2_mem_map_entry *entry = ((void*)tag) + off;
        unsigned long to_set = 0;
        unsigned long to_clear = 0;
        switch(entry->type) {
            case 1: // RAM
                to_set = PHYS_MEM_FLAGS_RAM|PHYS_MEM_FLAGS_AVAIL;
                break;
            case 3: // ACPI Reserved
                to_set = PHYS_MEM_FLAGS_RAM|PHYS_MEM_FLAGS_FW_RESV;
                to_clear = PHYS_MEM_FLAGS_AVAIL;
                break;
            case 4: // Needs to be saved on hibernation
                to_set = PHYS_MEM_FLAGS_RAM|PHYS_MEM_FLAGS_SAVE;
                to_clear = PHYS_MEM_FLAGS_AVAIL;
                break;
            case 5: // Defective RAM
                to_set = PHYS_MEM_FLAGS_RAM|PHYS_MEM_FLAGS_DEFECT;
                to_clear = PHYS_MEM_FLAGS_AVAIL;
                break;
            default: // Ignore this region
                to_set = PHYS_MEM_FLAGS_FW_IGNORE;
                to_clear = PHYS_MEM_FLAGS_AVAIL;
                dprintk("Found Unknown Region Type in MB2 Memory Info [%p-%p) type=%d!\n",
                        entry->base, entry->base + entry->length, entry->type);
                break;
        }
        res = mem_flags_set_flags(map, entry->base, entry->length, to_set);
        if(res) {
            return res;
        }
        res = mem_flags_clear_flags(map, entry->base, entry->length, to_clear);
        if(res) {
            return res;
        }
    }
    return 0;
}

static int
mb2_handle_basic_info(struct mb2_info_tag *tag, struct mem_flags *map) 
{
    int res;
    res = mem_flags_set_flags(map, 0x0, tag->basic_mem_info.mem_lower, PHYS_MEM_FLAGS_RAM|PHYS_MEM_FLAGS_AVAIL);
    if(res) {
        printk("Failed to add Multiboot2 basic_mem_info lower mem [%p - %p) to the memory map! (err=%s)\n",
                (uintptr_t)(0x0), (uintptr_t)(0x0 + tag->basic_mem_info.mem_lower), errnostr(res));
        return res;
    }
    res = mem_flags_set_flags(map, 0x100000, tag->basic_mem_info.mem_upper, PHYS_MEM_FLAGS_RAM|PHYS_MEM_FLAGS_AVAIL);
    if(res) {
        printk("Failed to add Multiboot2 basic_mem_info upper mem [%p - %p) to the memory map! (err=%s)\n",
                (uintptr_t)(0x100000), (uintptr_t)(0x100000 + tag->basic_mem_info.mem_upper), errnostr(res));
        return res;
    }
    return 0;
}

static int
mb2_init_memory_map(struct mb2_info *info, struct mem_flags *map) 
{
    int res = -1;
    struct mb2_memory_info mem_info = { 0 };

    mb2_info_for_each_tag(info, mb2_memory_info_handler, &mem_info);

    if(mem_info.mem_map_found) {
        res = mb2_handle_mem_flags(mem_info.mem_map_tag, map);
        if(res) {
            printk("Failed to get memory flags info from Multiboot2 mem_map tag (err=%s)\n",
                    errnostr(res));
        }
    }
    if(res && mem_info.basic_info_found) {
        res = mb2_handle_basic_info(mem_info.basic_info_tag, map);
        if(res) {
            printk("Failed to get memory flags info from Multiboot2 basic_mem_info tag (err=%s)\n",
                    errnostr(res));
        }
    }

    if(res) {
        return res;
    }

    return 0;
}

static int
mb2_mem_flags_init(void) 
{
    int res;
    res = mb2_init_memory_map(boot_mb2_info_ptr, get_phys_mem_flags());
    if(res) {
        return res;
    }

    return 0;
}

#ifdef CONFIG_MULTIBOOT2_MODULES
static void
mb2_module_reserve_handler(
        struct mb2_info *info,
        struct mb2_info_tag *tag,
        void *state)
{
    int *res = state;
    if(*res) {
        return;
    }
    switch(tag->hdr.type) {
        case MB2_INFO_TAG_TYPE_MODULE:
            *res = mem_flags_clear_flags(
                    get_phys_mem_flags(),
                    tag->module.mod_start,
                    tag->module.mod_end - tag->module.mod_start,
                    PHYS_MEM_FLAGS_AVAIL);
            break;
    }
}
#endif

static int
mb2_reserve_info_struct(void)
{
    int res;
    res = mem_flags_clear_flags(
            get_phys_mem_flags(),
            (uintptr_t)boot_mb2_info_ptr,
            boot_mb2_info_ptr->hdr.total_size,
            PHYS_MEM_FLAGS_AVAIL);

#ifdef CONFIG_MULTIBOOT2_MODULES
    mb2_info_for_each_tag(
            boot_mb2_info_ptr,
            mb2_module_reserve_handler,
            &res);
#endif

    return res;
}

declare_init_desc(mem_flags, mb2_mem_flags_init, "Initializing Physical Memory Flags from Multiboot2 Info");
declare_init_desc(post_mem_flags, mb2_reserve_info_struct, "Reserving Multiboot2 Info Structure");

