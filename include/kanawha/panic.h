#ifndef __KANAWHA__PANIC_H__
#define __KANAWHA__PANIC_H__

#include <kanawha/attribute.h>

int panic_printk_init(void);

// panic's get their own buffer, so that there's no need for locking
int do_panic_printk(const char *fmt, ...);

__noreturn
void do_panic(void);

#define panic(fmt, ...) \
    do {\
        do_panic_printk("[PANIC] (%s:%d): " fmt, (const char*)__FILE__, (int)__LINE__, ##__VA_ARGS__); \
        do_panic(); \
        while(1) {} \
    } while(0)

#endif
