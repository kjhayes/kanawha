
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
    return (size_t)((uintptr_t)__kernel_phys_end - (uintptr_t)__kernel_phys_start);
}

