#ifndef __KANAWHA__PRINTK_H__
#define __KANAWHA__PRINTK_H__

#include <stdarg.h>
#include <kanawha/common.h>
#include <kanawha/types.h>
#include <kanawha/time.h>
#include <kanawha/clk.h>
#include <kanawha/attribute.h>

typedef int(printk_handler_f)(char);

// returns 0 on success, 1 on error
//
// (You can pass this into "dump" functions, so they don't
//  have to be hard-coded to use "printk" and could technically
//  use any function which uses the same format string)
typedef int(printk_f)(const char *fmt, ...);

int do_printk(const char *fmt, ...);
int do_vprintk(const char *fmt, va_list args);

#define printk(fmt, ...) \
    do {\
        nsec_t time_ns = duration_to_nsec(current_timestamp()); \
        unsigned long __printk__sec = time_ns / NSEC_PER_SEC; \
        unsigned long __printk__sec_dec = time_ns % NSEC_PER_SEC; \
        do_printk("[%lu.%lu]: " fmt, __printk__sec, __printk__sec_dec, ##__VA_ARGS__); \
    } while(0)

#define eprintk(fmt, ...) \
    do {\
        nsec_t time_ns = duration_to_nsec(current_timestamp()); \
        unsigned long __printk__sec = time_ns / NSEC_PER_SEC; \
        unsigned long __printk__sec_dec = time_ns % NSEC_PER_SEC; \
        do_printk("[ERROR (%lu.%lu)]: " fmt, __printk__sec, __printk__sec_dec, ##__VA_ARGS__); \
    } while(0)

#define wprintk(fmt, ...) \
    do {\
        nsec_t time_ns = duration_to_nsec(current_timestamp()); \
        unsigned long __printk__sec = time_ns / NSEC_PER_SEC; \
        unsigned long __printk__sec_dec = time_ns % NSEC_PER_SEC; \
        do_printk("[WARN (%lu.%lu)]: " fmt, __printk__sec, __printk__sec_dec, ##__VA_ARGS__); \
    } while(0)


#ifdef DEBUG
#define dprintk(fmt, ...) \
    do {\
        nsec_t time_ns = duration_to_nsec(current_timestamp()); \
        unsigned long __printk__sec = time_ns / NSEC_PER_SEC; \
        unsigned long __printk__sec_dec = time_ns % NSEC_PER_SEC; \
        do_printk("[DEBUG (%lu.%lu)]: " fmt, __printk__sec, __printk__sec_dec, ##__VA_ARGS__); \
    } while(0)
#else
#define dprintk(fmt, ...)
#endif

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

int printk_init(void);
int printk_add_handler(printk_handler_f *handler);
int printk_remove_handler(printk_handler_f *handler);

int snprintk(char *buf, size_t buf_size, const char *fmt, ...);

#endif
