
#include <kanawha/vmem.h>
#include <kanawha/init.h>
#include <kanawha/stdint.h>
#include <kanawha/stddef.h>
#include <kanawha/errno.h>
#include <kanawha/slab.h>
#include <kanawha/percpu.h>
#include <kanawha/printk.h>
#include <kanawha/ptree.h>
#include <kanawha/thread.h>
#include <kanawha/process.h>
#include <kanawha/assert.h>
#include <arch/x64/mmu.h>

static DECLARE_SPINLOCK(vmem_map_slab_lock);
#define VMEM_MAP_SLAB_BUFFER_SIZE 0x1000
static uint8_t vmem_map_slab_buffer[VMEM_MAP_SLAB_BUFFER_SIZE];
static struct slab_allocator *vmem_map_slab_allocator = NULL;

static DECLARE_SPINLOCK(vmem_region_slab_lock);
#define VMEM_REGION_SLAB_BUFFER_SIZE 0x1000
static uint8_t vmem_region_slab_buffer[VMEM_REGION_SLAB_BUFFER_SIZE];
static struct slab_allocator *vmem_region_slab_allocator = NULL;

static DECLARE_SPINLOCK(vmem_region_ref_slab_lock);
#define VMEM_REGION_REF_SLAB_BUFFER_SIZE 0x1000
static uint8_t vmem_region_ref_slab_buffer[VMEM_REGION_REF_SLAB_BUFFER_SIZE];
static struct slab_allocator *vmem_region_ref_slab_allocator = NULL;

static int
init_vmem_mapping_allocators(void) 
{
    vmem_map_slab_allocator = create_static_slab_allocator(
            vmem_map_slab_buffer,
            VMEM_MAP_SLAB_BUFFER_SIZE,
            sizeof(struct vmem_map),
            orderof(struct vmem_map));

    if(vmem_map_slab_allocator == NULL) {
        return -ENOMEM;
    }

    vmem_region_slab_allocator = create_static_slab_allocator(
            vmem_region_slab_buffer,
            VMEM_REGION_SLAB_BUFFER_SIZE,
            sizeof(struct vmem_region),
            orderof(struct vmem_region));

    if(vmem_region_slab_allocator == NULL) {
        return -ENOMEM;
    }

    vmem_region_ref_slab_allocator = create_static_slab_allocator(
            vmem_region_ref_slab_buffer,
            VMEM_REGION_REF_SLAB_BUFFER_SIZE,
            sizeof(struct vmem_region_ref),
            orderof(struct vmem_region_ref));

    if(vmem_region_ref_slab_allocator == NULL) {
        return -ENOMEM;
    }

    return 0;
}
declare_init_desc(static, init_vmem_mapping_allocators, "Initializing Virtual Memory Region Slab Allocator(s)");

static struct vmem_region_ref *
alloc_vmem_region_ref(void) 
{
    spin_lock(&vmem_region_ref_slab_lock);
    if(vmem_region_ref_slab_allocator == NULL) {
        return NULL;
    }

    dprintk("alloc_vmem_region_ref: num slab objs = 0x%llx\n", (ull_t)slab_objs_free(vmem_region_ref_slab_allocator));
    struct vmem_region_ref *ref = (struct vmem_region_ref*)slab_alloc(vmem_region_ref_slab_allocator);
    dprintk("alloc_vmem_region_ref = %p\n", ref);
    spin_unlock(&vmem_region_ref_slab_lock);
    return ref;
}

static void
free_vmem_region_ref(struct vmem_region_ref *ref) 
{
    slab_free(vmem_region_ref_slab_allocator, ref);
}

struct vmem_map *
vmem_map_create(void)
{
    int res;
    spin_lock(&vmem_map_slab_lock);
    if(vmem_map_slab_allocator == NULL) {
        eprintk("Called vmem_map_create before vmem_map_slab_allocator has been initialized!\n");
        return NULL;
    }
    struct vmem_map *map = slab_alloc(vmem_map_slab_allocator);
    spin_unlock(&vmem_map_slab_lock);
    if(map == NULL) {
        eprintk("vmem_map_create: slab_alloc failed!\n");
        return map;
    }

    spinlock_init(&map->lock);
    ptree_init(&map->mapping_root);

    res = arch_vmem_map_init(map);
    if(res) {
        slab_free(vmem_map_slab_allocator, map);
        eprintk("arch_vmem_map_init failed! (err=%s)\n", errnostr(res));
        return NULL;
    }

    return map;
}

int
vmem_map_destroy(struct vmem_map *map)
{
    int res;

    do {
        struct ptree_node *region_node = ptree_get_first(&map->mapping_root);
        if(region_node == NULL) {
            break;
        }
        struct vmem_region_ref *ref =
            container_of(region_node, struct vmem_region_ref, map_node);
        res = vmem_map_unmap_region(map, ref);
        if(res) {
            eprintk("vmem_map_destroy failed to unmap vmem region!\n");
            return res;
        }
    } while(1);

    res = arch_vmem_map_deinit(map);
    if(res) {
        return res;
    }

    return 0;
}

struct vmem_region *
vmem_region_create_direct(
        paddr_t paddr,
        size_t size,
        unsigned long flags)
{
    int res;
    spin_lock(&vmem_region_slab_lock);
    struct vmem_region *region = slab_alloc(vmem_region_slab_allocator);
    spin_unlock(&vmem_region_slab_lock);
    if(region == NULL) {
        return NULL;
    }

    region->type = VMEM_REGION_TYPE_DIRECT;
    region->size = size;
    region->direct.phys_base = paddr;
    region->direct.flags = flags;

    spinlock_init(&region->lock);
    region->num_refs = 0;
    ilist_init(&region->ref_list);

    res = arch_vmem_region_init(region);
    if(res) {
        slab_free(vmem_region_slab_allocator, region);
        return NULL;
    }

    return region;
}

static int
default_page_fault_handler(
        struct vmem_region_ref *region_ref,
        uintptr_t offset,
        unsigned long access_flags,
        void *priv_state)
{
    eprintk("Unhandled Page Fault on vmem_region_ref %p, offset 0x%llx\n",
            region_ref, (ull_t)offset);

    return PAGE_FAULT_UNHANDLED;
}


struct vmem_region *
vmem_region_create_paged(
        size_t size,
        page_fault_f *fault_handler,
        void *priv_state)
{
    int res;
    struct vmem_region *region = slab_alloc(vmem_region_slab_allocator);
    if(region == NULL) {
        return NULL;
    }

    region->type = VMEM_REGION_TYPE_PAGED;
    region->size = size;
    region->paged.fault_handler =
        fault_handler ? fault_handler : default_page_fault_handler;
    region->paged.priv_state = priv_state;

    spinlock_init(&region->lock);
    region->num_refs = 0;
    ilist_init(&region->ref_list);

    res = arch_vmem_region_init(region);
    if(res) {
        slab_free(vmem_region_slab_allocator, region);
        return NULL;
    }

    return region;
}

int
vmem_region_destroy(
        struct vmem_region *region)
{
    int res;
    res = arch_vmem_region_deinit(region);
    if(res) {
        return res;
    }

    // TODO
    return -EUNIMPL;
}

struct vmem_region_ref *
vmem_map_get_region(struct vmem_map *map, vaddr_t addr) 
{
    dprintk("vmem_map_get_region(map=%p, addr=%p)\n",
            map, addr);

    struct ptree_node *node = ptree_get_max_less_or_eq(&map->mapping_root, addr);
    if(node == NULL) {
        return NULL;
    }

    struct vmem_region_ref *ref = container_of(node, struct vmem_region_ref, map_node);
    vaddr_t end = ref->virt_addr + ref->region->size;
    if(addr >= end) {
        return NULL;
    }
    return ref;
}

int
vmem_map_map_region(
        struct vmem_map *map,
        struct vmem_region *region,
        vaddr_t base)
{
    int res;
    vaddr_t end = base + region->size;

    DEBUG_ASSERT(KERNEL_ADDR(map));
    DEBUG_ASSERT(KERNEL_ADDR(region));

    spin_lock(&region->lock);
    spin_lock(&map->lock);

    { // Checking for overlap
    struct ptree_node *overlap_check_node = ptree_get_max_less_or_eq(&map->mapping_root, end-1);
    if(overlap_check_node != NULL) {
        struct vmem_region_ref *overlap_check_region =
            container_of(overlap_check_node, struct vmem_region_ref, map_node);
        vaddr_t overlap_end = overlap_check_region->virt_addr + overlap_check_region->region->size;
        if(overlap_end > base) {
            // We overlap with this region in virtual memory
            eprintk("Found overlapping region when trying to map vmem_region into vmem_map!\n");
            res = -EEXIST;
            goto err0;
        }
    }
    }
    
    // We don't overlap any existing region
    region->num_refs += 1;

    struct vmem_region_ref *ref = alloc_vmem_region_ref();
    if(ref == NULL) {
        eprintk("Failed to allocate vmem_region_ref!\n");
        goto err1;
    }

    ref->map = map;
    ref->region = region;
    ref->virt_addr = base; 

    ilist_push_tail(&region->ref_list, &ref->region_node);
    res = ptree_insert(&map->mapping_root, &ref->map_node, base);
    if(res) {
        eprintk("Failed to insert vmem_region_ref into vmem_map ptree tree! Region [%p - %p)\n",
                base, base + region->size);
        goto err2;
    }

    spin_unlock(&map->lock);
    spin_unlock(&region->lock);

    res = arch_vmem_map_map_region(map, ref);
    if(res) {
        eprintk("arch_vmem_map_map_region failed! (err=%s)\n", errnostr(res));
        goto err3;
    }

    return 0;

err3:
    ptree_remove(&map->mapping_root, base);
err2:
    ilist_remove(&region->ref_list, &ref->region_node);
    free_vmem_region_ref(ref);
err1:
    region->num_refs--;
err0:
    spin_unlock(&map->lock);
    spin_unlock(&region->lock);
    return res;
}

int
vmem_map_unmap_region(
        struct vmem_map *map,
        struct vmem_region_ref *ref)
{
    int res = 0;
    res = arch_vmem_map_unmap_region(map, ref);

    if(res) {
        return res;
    }

    spin_lock(&ref->region->lock);
    spin_lock(&map->lock);

    struct vmem_region *region = ref->region;

    struct ptree_node *removed = ptree_remove(&map->mapping_root, ref->virt_addr);
    DEBUG_ASSERT(removed == &ref->map_node);

    region->num_refs--;
    ilist_remove(&region->ref_list, &ref->region_node);

    spin_unlock(&map->lock);
    spin_unlock(&ref->region->lock);

    free_vmem_region_ref(ref);

    return 0;
}

int
vmem_map_flush(struct vmem_map *map) 
{
    int res;
    spin_lock(&map->lock);
    res = arch_vmem_map_flush(map);
    spin_unlock(&map->lock);
    return res;
}

int
vmem_region_flush(struct vmem_region *region) 
{
    int res;
    spin_lock(&region->lock);
    ilist_node_t *node;
    ilist_for_each(node, &region->ref_list)
    {
        struct vmem_region_ref *ref =
            container_of(node, struct vmem_region_ref, region_node);
        res = vmem_map_flush(ref->map);
        if(res) {
            spin_unlock(&region->lock);
            return res;
        }
    }
    spin_unlock(&region->lock);
    return 0;
}

DECLARE_STATIC_PERCPU_VAR(struct vmem_map *, current_vmem_map);

int vmem_map_activate(struct vmem_map *map)
{
    int res;

    struct vmem_map **current_map = percpu_ptr(percpu_addr(current_vmem_map));

    if(*current_map == map) {
        return 0;
    }

    struct vmem_map *lesser, *greater;
    lesser = (uintptr_t)*current_map < (uintptr_t)map ? *current_map : map;
    greater = (uintptr_t)*current_map < (uintptr_t)map ? map : *current_map;
   

    if(lesser) {spin_lock(&lesser->lock);}
    if(greater) {spin_lock(&greater->lock);}

    dprintk("Activating vmem_map %p on CPU %ld\n",
            map, (sl_t)current_cpu_id());

    //arch_dump_vmem_map(printk, map);

    res = arch_vmem_map_activate(map);
    if(res) {
        if(greater) {spin_unlock(&greater->lock);}
        if(lesser) {spin_unlock(&lesser->lock);}
        return res;
    }
    
    map->active_on++;
    if(*current_map) {
        (*current_map)->active_on--;
    }
    *current_map = map;

    if(greater) {spin_unlock(&greater->lock);}
    if(lesser) {spin_unlock(&lesser->lock);}

    return 0;
}

static struct vmem_map *default_map = NULL;
static struct vmem_region *identity_map_region = NULL;

int vmem_map_deactivate(void) 
{
    int res = 0;

    struct vmem_map **current_map_slot = percpu_ptr(percpu_addr(current_vmem_map));

    struct vmem_map *map = *current_map_slot;

    spin_lock(&map->lock);
    if(map != NULL && map != default_map) {
        res = vmem_map_activate(default_map);
    }
    spin_unlock(&map->lock);

    return res;
}

struct vmem_map *
vmem_map_get_current(void)
{
    // We assume the caller has dealt with the issue of preemption
    return *(struct vmem_map**)percpu_ptr(percpu_addr(current_vmem_map));
}

int
vmem_paged_region_map(
        struct vmem_region *region,
        size_t offset,
        paddr_t phys_addr,
        size_t size,
        unsigned long flags)
{
    if(offset + size > region->size) {
        return -ERANGE;
    }
    if(region->type != VMEM_REGION_TYPE_PAGED) {
        return -EINVAL;
    }
    return arch_vmem_paged_region_map(
            region,
            offset,
            phys_addr,
            size,
            flags);
}

int
vmem_paged_region_unmap(
        struct vmem_region *region,
        size_t offset,
        size_t size)
{
    if(offset + size > region->size) {
        return -ERANGE;
    }
    if(region->type != VMEM_REGION_TYPE_PAGED) {
        return -EINVAL;
    }
    return arch_vmem_paged_region_unmap(
            region,
            offset,
            size);
}

/*
 * Virtual Memory Initialization
 */

struct vmem_map *
vmem_get_default_map(void) {
    return default_map;
}

int
vmem_force_mapping(struct vmem_region *region, vaddr_t virtual_address)
{
    int res;
    res = vmem_map_map_region(
            default_map,
            region,
            virtual_address);

    if(res) {
        eprintk("vmem_force_mapping: Failed to map into the default map! (err=%s)\n",
                errnostr(res));
        return res;
    }

    res = thread_force_mapping(region, virtual_address);
    if(res) {
        eprintk("vmem_force_mapping: thread_force_mapping returned (%s)!\n",
                errnostr(res));
        return res;
    }

    return 0;
}
int
vmem_relax_mapping(vaddr_t virtual_address)
{
    return -EUNIMPL;
}

static int
vmem_map_unhandled_user_page_fault(
        vaddr_t faulting_address,
        unsigned long access_flags,
        struct vmem_map *map)
{
    int res;

    struct process *process = current_process();
    if(!KERNEL_ADDR(process)) {
        eprintk("User Page Fault without a current process!\n");
        return -EINVAL;
    }

    // We need to terminate the process
    // TODO: Signal something like SIGSEGV once we have
    // signalling implemented

    eprintk("Terminating PID(%ld) for Invalid Memory Access!\n",
            (sl_t)process->id);

    res = process_terminate(process, 1);
    if(res) {
        eprintk("Failed to terminate PID(%ld)! (err=%s)\n", 
                (sl_t)process->id,
                errnostr(res));
        return res;
    }

    thread_abandon(force_resched());
    return 0;
}

int
vmem_map_handle_page_fault(
        vaddr_t faulting_address,
        unsigned long access_flags,
        struct vmem_map *map)
{
    DEBUG_ASSERT(KERNEL_ADDR(map));

    struct vmem_region_ref *ref =
        vmem_map_get_region(map, faulting_address);

    int res;

    if(ref == NULL) {
        res = PAGE_FAULT_UNHANDLED;
    }
    else {
        struct vmem_region *region = ref->region;
        if(region->type != VMEM_REGION_TYPE_PAGED) {
            eprintk("Page Fault in non-paged vmem region! region=%p ref=%p (unexpected)\n", region, ref);
            return -EINVAL;
        }

        uintptr_t offset = faulting_address - ref->virt_addr;
        res = (region->paged.fault_handler)(ref, offset, access_flags, region->paged.priv_state);
    }

    switch(res) {
        case PAGE_FAULT_HANDLED:
            return 0;
        case PAGE_FAULT_UNHANDLED:

            eprintk("Unhandled Page Fault! (addr=%p) %s%s%s%s%s\n",
                    faulting_address,
                    (access_flags & PF_FLAG_NOT_PRESENT ? "[NOT_PRESENT]" : ""),
                    (access_flags & PF_FLAG_READ ? "[READ]" : ""),
                    (access_flags & PF_FLAG_WRITE ? "[WRITE]" : ""),
                    (access_flags & PF_FLAG_EXEC ? "[EXEC]" : ""),
                    (access_flags & PF_FLAG_USERMODE ? "[USERMODE]" : "")
                    );
 
            if(access_flags & PF_FLAG_USERMODE) {
                res = vmem_map_unhandled_user_page_fault(
                        faulting_address,
                        access_flags,
                        map);
                return res; // res should be zero assuming there are no kernel errors,
                            // even if we end up killing the user-process
            } else {
               return -EINVAL;
            }
             
            return -EINVAL;
        default:
            eprintk("vmem_region page fault handler returned unknown value (%d)\n", res);
            return -EINVAL;
    }
}

static int
vmem_create_default_kernel_map(void)
{
    int res;

    default_map = vmem_map_create();
    if(default_map == NULL) {
        eprintk("OOM Error when initializing default kernel vmem_map!\n");
        return -ENOMEM;
    }

    size_t phys_mem_mapping_size = (1ULL << CONFIG_IDENTITY_MAP_ORDER);
    identity_map_region = vmem_region_create_direct(
            0x0,
            phys_mem_mapping_size,
            VMEM_REGION_EXEC|VMEM_REGION_WRITE|VMEM_REGION_READ);

    if(identity_map_region == NULL) {
        eprintk("OOM Error when initializing default kernel vmem_region!\n");
        return -ENOMEM;
    }

    res = vmem_force_mapping(
            identity_map_region,
            CONFIG_VIRTUAL_BASE);
    if(res) {
        eprintk("Failed to map identity map vmem_region into default vmem_map! (err=%s)\n", errnostr(res));
        return res;
    }

    return 0;
}
declare_init_desc(vmem, vmem_create_default_kernel_map, "Creating Default Kernel Virtual Memory Mapping");

int
vmem_percpu_init(void)
{
    if(default_map == NULL) {
        return -EDEFER;
    }
    return vmem_map_activate(default_map);
}
declare_init_desc(post_vmem, vmem_percpu_init, "Activating default kernel vmem_map on BSP");

