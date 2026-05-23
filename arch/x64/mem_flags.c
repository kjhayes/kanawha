
#include <kanawha/init.h>
#include <kanawha/mem_flags.h>

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
virt_mem_flags_reserve_ident_map(void)
{
    int res;

    res = mem_flags_clear_flags(get_virt_mem_flags(),
                                CONFIG_IDMAP_VIRTUAL_BASE,
                                (1ULL << CONFIG_IDMAP_SIZE_ORDER),
                                VIRT_MEM_FLAGS_AVAIL);

    if(res)
    {
        return res;
    }

    return 0;
}
declare_init_desc(mem_flags,
                  virt_mem_flags_reserve_ident_map,
                  "Reserving the Kernel Identity Map in Virtual Memory");
