
#include <arch/x64/cpuid.h>
#include <kanawha/init.h>

static int
cpuid_boot_check(void) {
    if(!x64_cpuid_supported()) {
        eprintk("Processor Does Not Support CPUID Instruction! (Required by Kanawha)\n");
        return -EINVAL;
    }
    return 0;
}
declare_init_desc(boot, cpuid_boot_check, "Checking for CPUID Support");

