
#include <kanawha/init.h>
#include <kanawha/printk.h>
#include <kanawha/errno.h>
#include <arch/riscv64/sbi.h>

#define SBI_EXT_DBGCON 0x4442434E

static int
sbi_boot_console_printk_handler(char c) {
    struct sbiret ret = sbi_ecall(
            SBI_EXT_DBGCON, // Extension
            0x2, // Function
            (uint64_t)c,
            0,0,0,0,0);
    switch(ret.error) {
        case SBI_SUCCESS:
            return 0;
        case SBI_ERR_DENIED:
            return -EPERM;
        case SBI_ERR_FAILED:
            return -EFAULT;
        default:
            return -EINVAL;
    }
    return 0;
}

static int
sbi_boot_console_init(void)
{
    int res;

    res = sbi_probe_extension(SBI_EXT_DBGCON);
    if(res) {
        return res;
    }

    res = printk_add_handler(sbi_boot_console_printk_handler);
    if(res) {
        return res;
    }

    return 0;
}
declare_init_desc(boot, sbi_boot_console_init, "Registering Boot SBI Console");
