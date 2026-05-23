
#include <kanawha/init.h>
#include <kanawha/mem_flags.h>
#include <arch/x64/mmu.h>

extern int __kernel_phys_start[];
extern int __kernel_phys_end[];

void __phys *
arch_kernel_phys_start(void)
{
    return (void __phys *)__kernel_phys_start;
}
size_t
arch_kernel_phys_size(void)
{
    return (size_t)((uintptr_t)__kernel_phys_end -
                    (uintptr_t)__kernel_phys_start);
}

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
