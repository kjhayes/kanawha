#ifndef __KANAWHA__USERMODE_H__
#define __KANAWHA__USERMODE_H__

#define __user __attribute__((address_space(3)))

__attribute__((noreturn))
void enter_usermode(void __user *starting_address);

__attribute__((noreturn))
void arch_enter_usermode(void __user *starting_address);

#endif
