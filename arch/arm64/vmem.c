
#include <kanawha/vmem.h>

int
arch_vmem_map_init(struct vmem_map *map)
{
    return -EUNIMPL;
}

int
arch_vmem_map_deinit(struct vmem_map *map)
{
    return -EUNIMPL;
}

static int
arch_vmem_region_init_direct(struct vmem_region *region)
{
    return -EUNIMPL;
}

static int
arch_vmem_region_init_paged(struct vmem_region *region)
{
    return -EUNIMPL;
}

int
arch_vmem_region_init(struct vmem_region *region)
{
    switch(region->type)
    {
    case VMEM_REGION_TYPE_DIRECT:
        return arch_vmem_region_init_direct(region);
    case VMEM_REGION_TYPE_PAGED:
        return arch_vmem_region_init_paged(region);
    default:
        return -EINVAL;
    }
}

int
arch_vmem_region_deinit(struct vmem_region *region)
{
    return -EUNIMPL;
}

int
arch_vmem_map_map_region(struct vmem_map *map, struct vmem_region_ref *ref)
{
    return -EUNIMPL;
}

int
arch_vmem_map_unmap_region(struct vmem_map *map, struct vmem_region_ref *ref)
{
    return -EUNIMPL;
}

int
arch_vmem_paged_region_map(struct vmem_region *region,
                           size_t offset,
                           void __phys *phys_addr,
                           size_t size,
                           unsigned long flags)
{
    return -EUNIMPL;
}

int
arch_vmem_paged_region_unmap(struct vmem_region *region,
                             size_t offset,
                             size_t size)
{
    return -EUNIMPL;
}

int
arch_vmem_map_activate(struct vmem_map *map)
{
    return -EUNIMPL;
}

int
arch_vmem_map_flush(struct vmem_map *map)
{
    return -EUNIMPL;
}

order_t
arch_vmem_region_alignment(struct vmem_region *region)
{
    return 12; // TODO (This may not be correct)
}

void
arch_dump_vmem_map(printk_f *printer, struct vmem_map *map)
{
    (*printer)("arch_dump_vmem_map is unimplemented!\n");
    return;
}
