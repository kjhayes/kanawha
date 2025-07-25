
#include <arch/x64/fpu.h>

int arch_on_process_entry(void)
{
    int res;

    res = x64_fpu_per_process_init();
    if(res) {
        return res;
    }

    return 0;
}

