
#include <arch/x64/fpu.h>
#include <arch/x64/sysreg.h>

static
int x64_fpu_init_any(void) 
{
    uint32_t cr0 = read_cr0();
    cr0 &= ~(1UL << 2); // Disable x87 Emulation
    cr0 &= ~(1UL << 3); // Disable Task Switch Trapping
    cr0 |=  (1UL << 4); // 387 or later (probably already hardwired)
    write_cr0(cr0);

    uint64_t cr4 = read_cr4();
    cr4 |=  (1UL << 9); // Enable 128-bit SSE
    cr4 |=  (1UL << 10); // Enable 128-bit SSE Exceptions
    write_cr4(cr4);

    return 0;
}

int x64_fpu_init_bsp(void) 
{
    return x64_fpu_init_any();
}

int x64_fpu_init_ap(void) 
{
    return x64_fpu_init_any();
}

