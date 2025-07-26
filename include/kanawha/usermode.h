#ifndef __KANAWHA__USERMODE_H__
#define __KANAWHA__USERMODE_H__

#include <kanawha/attribute.h>

__noreturn
void enter_usermode(void *arg);

__noreturn
void arch_enter_usermode(void __user *starting_address, void *arg);

#endif
