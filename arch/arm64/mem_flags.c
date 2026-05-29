
#include <kanawha/init.h>
#include <kanawha/mem_flags.h>
#include <kanawha/vmem.h>

extern uint8_t __kernel_virt_start[];
extern uint8_t __kernel_virt_end[];
static void __phys *kernel_virt_start = (void __phys *)&__kernel_virt_start;
static void __phys *kernel_virt_end = (void __phys *)&__kernel_virt_end;

extern uint8_t __kernel_boot_start[];
extern uint8_t __kernel_boot_end[];
static void __phys *volatile kernel_boot_start =
    (void __phys *)__kernel_boot_start;
static void __phys *volatile kernel_boot_end = (void __phys *)__kernel_boot_end;



void __phys *
arch_kernel_phys_start(void)
{
    return (void __phys *)(uintptr_t)CONFIG_ARM64_LINKED_PHYS_BASE;
}

size_t
arch_kernel_phys_size(void)
{
    return ((size_t)((uintptr_t)kernel_virt_end -
                     (uintptr_t)kernel_virt_start)) +
           ((size_t)((uintptr_t)kernel_boot_end -
                     (uintptr_t)kernel_boot_start));
}

static int
arm64_virt_flags_static_init(void)
{
    int res;

    struct mem_flags *vflags = get_virt_mem_flags();

#define HIGHMEM_BASE (~((1ULL << 48) - 1))
#define HIGHMEM_SIZE (1ULL << 48)
#define LOWMEM_BASE 0x0
#define LOWMEM_SIZE (1ULL << 48)

    printk("Setting Region [%p - %p) as Canonical Low Memory\n",
           LOWMEM_BASE,
           LOWMEM_BASE + LOWMEM_SIZE);

    res = mem_flags_clear_flags(vflags,
                                LOWMEM_BASE,
                                LOWMEM_SIZE,
                                VIRT_MEM_FLAGS_NONCANON);
    if(res)
    {
        return res;
    }

    printk("Setting Region [%p - %p) as Canonical High Memory\n",
           HIGHMEM_BASE,
           HIGHMEM_BASE + (HIGHMEM_SIZE - 1));

    res = mem_flags_clear_flags(vflags,
                                HIGHMEM_BASE,
                                HIGHMEM_SIZE - 1,
                                VIRT_MEM_FLAGS_NONCANON);
    if(res)
    {
        return res;
    }

    res = mem_flags_set_flags(vflags,
                              HIGHMEM_BASE,
                              HIGHMEM_SIZE - 1,
                              VIRT_MEM_FLAGS_HIGHMEM);
    if(res)
    {
        return res;
    }

    // Reserve the kernel in high-mem
    printk("Reserving the Kernel in Virtual Memory [%p - %p)\n",
           __kernel_virt_start,
           __kernel_virt_end);
    res = mem_flags_check_region(vflags,
                                 (uintptr_t)__kernel_virt_start,
                                 (__kernel_virt_end - __kernel_virt_start),
                                 VIRT_MEM_FLAGS_AVAIL | VIRT_MEM_FLAGS_HIGHMEM,
                                 0);
    if(res)
    {
        eprintk("Failed to reserve kernel in virtual memory! (err=%s)\n",
                errnostr(res));
        virt_mem_flags_dump();
        return res;
    }

    res = mem_flags_clear_flags(vflags,
                                (uintptr_t)__kernel_virt_start,
                                (__kernel_virt_end - __kernel_virt_start),
                                VIRT_MEM_FLAGS_AVAIL);
    if(res) {
        return res;
    }
    return 0;
}
declare_init_desc(mem_flags,
                  arm64_virt_flags_static_init,
                  "Setting ARM64 Virtual Memory Types");

static struct vmem_region *kernel_map_region = NULL;

static int
arm64_map_kernel_region(void)
{
    int res;

    size_t map_size = (arch_kernel_phys_size() + 0xFFF) & ~0xFFF;
    kernel_map_region = vmem_region_create_direct(
        arch_kernel_phys_start(),
        map_size,
        VMEM_REGION_EXEC | VMEM_REGION_WRITE | VMEM_REGION_READ);

    if(kernel_map_region == NULL)
    {
        eprintk("OOM Error when initializing default kernel vmem_region!\n");
        return -ENOMEM;
    }

    res = vmem_force_mapping(kernel_map_region,
                             (void *)CONFIG_ARM64_KERNEL_VIRTUAL_BASE);
    if(res)
    {
        eprintk("Failed to map kernel vmem_region into default vmem_map! "
                "(err=%s)\n",
                errnostr(res));
        return res;
    }

    return 0;
}

declare_init_desc(vmem,
                  arm64_map_kernel_region,
                  "Creating Kernel Virtual Memory Region");
