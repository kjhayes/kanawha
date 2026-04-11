
#include <kanawha/init.h>
#include <kanawha/mem_flags.h>

void __phys *
arch_kernel_phys_start(void) {
    panic("arch_kernel_phys_start");
    return NULL;
}

size_t
arch_kernel_phys_size(void)
{
    panic("arch_kernel_phys_size");
    return 0;
}


