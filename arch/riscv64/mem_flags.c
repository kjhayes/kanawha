
#include <kanawha/mem_flags.h>

extern uint8_t __kernel_virt_start[];
extern uint8_t __kernel_virt_end[];

void __phys *
arch_kernel_phys_start(void)
{
    panic("arch_kernel_phys_start is unimplemented!\n");
}
size_t
arch_kernel_phys_size(void)
{
    return (size_t)((uintptr_t)__kernel_virt_end - (uintptr_t)__kernel_virt_start);
}

