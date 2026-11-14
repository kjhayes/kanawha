
#include <arch/x64/cpuid.h>
#include <kanawha/init.h>

// asm Routines
extern int
__x64_cpuid_supported(void);

extern int
__x64_cpuid_ext(
        uint32_t eax,
        uint32_t ecx,
        struct x64_cpuid *id);

int
x64_cpuid_supported(void)
{
    return __x64_cpuid_supported();
}

int
x64_cpuid_ext(
        uint32_t eax,
        uint32_t ecx,
        struct x64_cpuid *id)
{
    return __x64_cpuid_ext(
            eax,
            ecx,
            id);
}

static int
cpuid_boot_check(void)
{
    if(!x64_cpuid_supported())
    {
        eprintk("Processor Does Not Support CPUID Instruction! (Required by "
                "Kanawha)\n");
        return -EINVAL;
    }
    return 0;
}
declare_init_desc(boot, cpuid_boot_check, "Checking for CPUID Support");
