
#include <kanawha/mem_flags.h>

extern uint8_t __kernel_virt_start[];
extern uint8_t __kernel_virt_end[];

void __phys *
arch_kernel_phys_start(void)
{
    return CONFIG_KERNEL_LOAD_ADDR;
}
size_t
arch_kernel_phys_size(void)
{
    return (size_t)((uintptr_t)__kernel_virt_end - (uintptr_t)__kernel_virt_start);
}

