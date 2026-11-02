#ifndef __KANAWHA__PRINTK_H__
#define __KANAWHA__PRINTK_H__

#include <kanawha/attribute.h>
#include <kanawha/clk.h>
#include <kanawha/common.h>
#include <kanawha/time.h>
#include <kanawha/types.h>
#include <kanawha/fmt.h>
#include <stdarg.h>

struct printer;

extern void printk_lock_acquire(void);
extern void printk_lock_release(void);

typedef int(printk_handler_f)(char);

// returns 0 on success, 1 on error
//
// (You can pass this into "dump" functions, so they don't
//  have to be hard-coded to use "printk" and could technically
//  use any function which uses the same format string)
typedef int(printk_f)(const char *fmt, ...);

int
do_printk(const char *fmt, ...);
int
do_vprintk(const char *fmt, va_list args);

#define printk(fmt, ...)                                                       \
    do {\
        printk_lock_acquire();\
        fmt_print(printk_printer(), "[%t]: " fmt, current_timestamp(), ##__VA_ARGS__);\
        printk_lock_release();\
    } while(0)

#define eprintk(fmt, ...)\
    do {\
        printk_lock_acquire();\
        fmt_print(printk_printer(), "[%t] ERROR: " fmt, current_timestamp(), ##__VA_ARGS__);\
        printk_lock_release();\
    } while(0)

#define wprintk(fmt, ...)\
    do {\
        printk_lock_acquire();\
        fmt_print(printk_printer(), "[%t] WARNING: " fmt, current_timestamp(), ##__VA_ARGS__);\
        printk_lock_release();\
    } while(0)

#ifdef DEBUG
#define dprintk(fmt, ...)\
    do {\
        printk_lock_acquire();\
        fmt_print(printk_printer(), "[%t] WARNING: " fmt, current_timestamp(), ##__VA_ARGS__);\
        printk_lock_release();\
    } while(0)
#else
#define dprintk(fmt, ...)
#endif

int
printk_init(void);
int
printk_add_handler(printk_handler_f *handler);
int
printk_remove_handler(printk_handler_f *handler);

// Printers
struct printer *
printk_printer(void);

#endif
