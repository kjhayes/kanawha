
#include <kanawha/printk.h>
#include <kanawha/usermode.h>

__noreturn void
arch_enter_usermode(void __user *starting_address, void *arg)
{
    panic("arch_enter_usermode is unimplemented!");
}
