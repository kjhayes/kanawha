#ifndef __KANAWHA__PRINTK_H__
#define __KANAWHA__PRINTK_H__

#include <kanawha/common.h>
#include <kanawha/stdint.h>

typedef void(printk_early_handler_f)(char);

// returns 0 on success, 1 on error
//
// (You can pass this into "dump" functions, so they don't
//  have to be hard-coded to use "printk" and could technically
//  use any function which uses the same format string)
typedef int(printk_f)(const char *fmt, ...);

int printk(const char *fmt, ...);

#define eprintk(fmt, ...) \
    do {\
        printk("[ERROR]: " fmt, ##__VA_ARGS__); \
    } while(0)

#define wprintk(fmt, ...) \
    do {\
        printk("[WARN]: " fmt, ##__VA_ARGS__); \
    } while(0)


#ifdef DEBUG
#define dprintk(fmt, ...) \
    do {\
        printk("[DEBUG]: " fmt, ##__VA_ARGS__); \
    } while(0)
#else
#define dprintk(fmt, ...)
#endif

// panic's get their own buffer, so that there's no need for locking
int panic_printk(const char *fmt, ...);

__attribute__((noreturn))
void do_panic(void);

#define panic(fmt, ...) \
    do {\
        panic_printk("[PANIC] (%s:%d): " fmt, (const char*)__FILE__, (int)__LINE__, ##__VA_ARGS__); \
        do_panic(); \
    } while(0)

int printk_early_init(void);
int printk_early_add_handler(printk_early_handler_f *handler);

int snprintk(char *buf, size_t buf_size, const char *fmt, ...);

#endif
