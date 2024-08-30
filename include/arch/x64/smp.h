#ifndef __KANAWHA__X64_SMP_H__
#define __KANAWHA__X64_SMP_H__

#include <kanawha/cpu.h>

int
x64_ap_notify_booted(void);

cpu_id_t
x64_get_booting_ap(void);


#endif
