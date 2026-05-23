
#include <kanawha/init.h>
#include <kanawha/mem_flags.h>
#include <kanawha/vmem.h>

static struct vmem_region *identity_map_region = NULL;

size_t idmap_virtual_base = CONFIG_IDMAP_VIRTUAL_BASE_AT_BOOT;

static int
idmap_map_into_vmem(void *virtual_base)
{
    int res;

    size_t phys_mem_mapping_size = (1ULL << CONFIG_IDMAP_SIZE_ORDER);
    identity_map_region = vmem_region_create_direct(
        0x0,
        phys_mem_mapping_size,
        VMEM_REGION_EXEC | VMEM_REGION_WRITE | VMEM_REGION_READ);

    if(identity_map_region == NULL)
    {
        eprintk("OOM Error when initializing default kernel vmem_region!\n");
        return -ENOMEM;
    }

    res = vmem_force_mapping(identity_map_region,
                             virtual_base);
    if(res)
    {
        eprintk("Failed to map identity map vmem_region into default "
                "vmem_map! "
                "(err=%s)\n",
                errnostr(res));
        return res;
    }

    idmap_virtual_base = (uintptr_t)virtual_base;

    return 0;
}

static int
idmap_init_vmem(void)
{
    int res;
    void *virtual_base;

#ifdef CONFIG_IDMAP_SELECT_VIRTUAL_BASE_STATIC
    virtual_base = (void*)CONFIG_IDMAP_STATIC_VIRTUAL_BASE;
#else /* CONFIG_IDMAP_SELECT_VIRTUAL_BASE_DYNAMIC */
#ifndef CONFIG_IDMAP_SELECT_VIRTUAL_BASE_DYNAMIC
#error "One of CONFIG_IDMAP_SELECT_VIRTUAL_BASE_STATIC or CONFIG_IDMAP_SELECT_VIRTUAL_BASE_DYNAMIC must be set!"
#endif
    res = mem_flags_find_and_reserve(
            get_virt_mem_flags(),
            1UL<<CONFIG_IDMAP_SIZE_ORDER,
            CONFIG_IDMAP_DYNAMIC_ALIGN_ORDER,
            VIRT_MEM_FLAGS_AVAIL|VIRT_MEM_FLAGS_HIGHMEM,
            VIRT_MEM_FLAGS_NONCANON,
            0,
            VIRT_MEM_FLAGS_AVAIL,
            &virtual_base);
    if(res) {
        return res;
    }
#endif

    return idmap_map_into_vmem(virtual_base);
}

declare_init_desc(vmem,
                  idmap_init_vmem,
                  "Creating Identity Map Virtual Memory Region");

static int
idmap_reserve_virt_mem(void)
{
    int res;

    res = mem_flags_clear_flags(get_virt_mem_flags(),
                                CONFIG_IDMAP_STATIC_VIRTUAL_BASE,
                                (1ULL << CONFIG_IDMAP_SIZE_ORDER),
                                VIRT_MEM_FLAGS_AVAIL);

    if(res)
    {
        return res;
    }

    return 0;
}
declare_init_desc(mem_flags,
                  idmap_reserve_virt_mem,
                  "Reserving the Kernel Identity Map in Virtual Memory");
