
#include <kanawha/vmem.h>
#include <kanawha/init.h>
#include <kanawha/mem_flags.h>
#include <arch/x64/mmu.h>

static struct vmem_region *identity_map_region = NULL;

static int
x64_map_identity_map_region(void)
{
    int res;

    size_t phys_mem_mapping_size = (1ULL << CONFIG_X64_IDENTITY_MAP_ORDER);
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
                             (void *)CONFIG_X64_VIRTUAL_BASE);
    if(res)
    {
        eprintk("Failed to map identity map vmem_region into default "
                "vmem_map! "
                "(err=%s)\n",
                errnostr(res));
        return res;
    }

    return 0;
}

declare_init_desc(vmem,
                  x64_map_identity_map_region,
                  "Creating Identity Map Virtual Memory Region");

static int
x64_virt_flags_static_init(void)
{
    int res;

    struct mem_flags *vflags = get_virt_mem_flags();
    printk("Setting Region [%p - %p) as Canonical Low Memory\n",
           0x0,
           X64_PML4_LOWMEM_SIZE);

    res = mem_flags_clear_flags(vflags,
                                0x0,
                                X64_PML4_LOWMEM_SIZE,
                                VIRT_MEM_FLAGS_NONCANON);
    if(res)
    {
        return res;
    }

    printk("Setting Region [%p - %p) as Canonical High Memory\n",
           X64_PML4_HIGHMEM_BASE,
           X64_PML4_HIGHMEM_BASE + (X64_PML4_HIGHMEM_SIZE - 1));

    res = mem_flags_clear_flags(vflags,
                                X64_PML4_HIGHMEM_BASE,
                                X64_PML4_HIGHMEM_SIZE - 1,
                                VIRT_MEM_FLAGS_NONCANON);
    if(res)
    {
        return res;
    }

    res = mem_flags_set_flags(vflags,
                              X64_PML4_HIGHMEM_BASE,
                              X64_PML4_HIGHMEM_SIZE - 1,
                              VIRT_MEM_FLAGS_HIGHMEM);
    if(res)
    {
        return res;
    }

    return 0;
}
declare_init_desc(mem_flags,
                  x64_virt_flags_static_init,
                  "Setting x64 Virtual Memory Types");

