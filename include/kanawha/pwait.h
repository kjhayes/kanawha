#ifndef __KANAWHA__PWAIT_H__
#define __KANAWHA__PWAIT_H__

#include <kanawha/pointer.h>

// "Physical" Wait/Wake Functions
// (backing for "mwait/mwake" syscalls)

int
pwait_on(void __phys *addr);
int
pwake_all(void __phys *addr);
int
pwake_single(void __phys *addr);

#endif
