
#include <devicetree/devicetree.h>
#include <devicetree/flat.h>
#include <devicetree/types.h>

#include <kanawha/mem_flags.h>
#include <kanawha/init.h>
#include <kanawha/vmem.h>
#include <kanawha/string.h>

static int
fdt_find_memory(void)
{
    int res;
    struct mem_flags *phys_map = get_phys_mem_flags();

    struct device_tree *dev_tree = devicetree_get();
    if(dev_tree == NULL) {
        return -EDEFER;
    }

    struct fdt __phys *phys_fdt = dev_tree->backing_data;
    struct fdt *fdt = __va(phys_fdt);

    DEBUG_ASSERT(fdt_check_header(fdt) == 0);

    struct fdt_node *memory_node = fdt_find_node_by_unitname(fdt, "memory");
    if(memory_node == NULL) {
        eprintk("Could not find FDT node \"memory\"!\n");
        return -ENXIO;
    }

    { // Checking Device Type
    struct fdt_property *device_type = fdt_find_property_by_name(fdt, memory_node, "device_type");
    if(device_type == NULL) {
        wprintk("FDT \"memory\" node is missing \"device_type\" property\n");
    } else {
        size_t len = fdt_property_size(fdt, device_type);
        char *value = fdt_property_data(fdt, device_type);
        if(strncmp("memory", value, len)) {
            wprintk("FDT \"memory\" node has invalid \"device_type\" property!\n");
        }
    }
    }

    size_t num_regs = fdt_node_reg_count(fdt, memory_node);

    void __phys *addr_buf[num_regs];
    size_t size_buf[num_regs];

    res = fdt_node_read_reg(
            fdt,
            memory_node,
            num_regs,
            addr_buf,
            size_buf);
    if(res) {
        return res;
    }

    for(size_t i = 0; i < num_regs; i++) {
        res = mem_flags_set_flags(
                phys_map,
                (uintptr_t)addr_buf[i],
                size_buf[i],
                PHYS_MEM_FLAGS_RAM|PHYS_MEM_FLAGS_AVAIL);
        if(res) {
            return res;
        }
    }

    struct fdt_node *resv_memory_node = fdt_find_node_by_unitname(fdt, "reserved-memory");
    if(resv_memory_node != NULL) {
        struct fdt_node *resv_child = fdt_node_first_subnode(fdt, resv_memory_node);
        while(resv_child) {
            size_t num_reg = fdt_node_reg_count(fdt, resv_child);
            void __phys * bases[num_reg];
            size_t sizes[num_reg];
            res = fdt_node_read_reg(fdt, resv_child, num_reg, bases, sizes);
            if(res) {
                wprintk("Failed to read reg property of reserved memory region in device tree! (err=%s)\n",
                        errnostr(res));
                resv_child = fdt_node_next_subnode(fdt, resv_child);
                continue;
            }

            // Check for other properties
            struct fdt_property *no_map_prop = fdt_find_property_by_name(fdt, resv_child, "nomap");
            if(no_map_prop != NULL) {
                wprintk("Device tree reserved-memory node has \"nomap\" property, which is not supported! (ignoring)\n");
            }

            for(size_t i = 0; i < num_reg; i++) {
                res = mem_flags_set_flags(
                    phys_map,
                    (uintptr_t)bases[i],
                    sizes[i],
                    PHYS_MEM_FLAGS_FW_RESV);
                res = mem_flags_clear_flags(
                    phys_map,
                    (uintptr_t)bases[i],
                    sizes[i],
                    PHYS_MEM_FLAGS_AVAIL);
            }

            resv_child = fdt_node_next_subnode(fdt, resv_child);
        }
    }

    // Traverse the FDT reserved memory regions
    uint32_t rsvmap_offset = fdttoh32(fdt->hdr.off_mem_rsvmap);
    struct fdt_reserve_entry *entry = ((void*)fdt) + rsvmap_offset;

    while(fdttoh64(entry->size) != 0) {
        uint64_t addr = fdttoh64(entry->address);
        uint64_t size = fdttoh64(entry->size);
        res = mem_flags_set_flags(
                phys_map,
                addr,
                size,
                PHYS_MEM_FLAGS_FW_RESV);
        if(res) {
            wprintk("Failed to mark physical memory region [%p - %p) as firmware reserved!\n",
                    addr,
                    size);
            entry++;
            continue;
        }
        res = mem_flags_clear_flags(
                phys_map,
                addr,
                size,
                PHYS_MEM_FLAGS_AVAIL);
        if(res) {
            wprintk("Failed to mark physical memory region [%p - %p) as unavailable!\n",
                    addr,
                    size);
            entry++;
            continue;
        }
        entry++;
    }

    return 0;
}

declare_init_desc(mem_flags, fdt_find_memory, "Finding Memory Region(s) in FDT");

