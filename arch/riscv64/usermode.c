
#include <kanawha/usermode.h>
#include <kanawha/printk.h>

__attribute__((noreturn))
void arch_enter_usermode(void __user *starting_address, void *arg)
{
    panic("arch_enter_usermode is unimplemented on riscv!");
}

