#ifndef __KANAWHA__PRINTK_H__
#define __KANAWHA__PRINTK_H__

#include <kanawha/panic.h>

#include <kanawha/attribute.h>
#include <kanawha/clk.h>
#include <kanawha/common.h>
#include <kanawha/time.h>
#include <kanawha/types.h>
#include <stdarg.h>

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
    do                                                                         \
    {                                                                          \
        do_printk("[%t]: " fmt,                                           \
                  current_timestamp(), \
                  ##__VA_ARGS__);                                              \
    } while(0)

#define eprintk(fmt, ...)                                                      \
    do                                                                         \
    {                                                                          \
        do_printk("[ERROR (%t)]: " fmt,                                   \
                  current_timestamp(), \
                  ##__VA_ARGS__);                                              \
    } while(0)

#define wprintk(fmt, ...)                                                      \
    do                                                                         \
    {                                                                          \
        do_printk("[WARN (%t)]: " fmt,                                    \
                  current_timestamp(),                                           \
                  ##__VA_ARGS__);                                              \
    } while(0)

#ifdef DEBUG
#define dprintk(fmt, ...)                                                      \
    do                                                                         \
    {                                                                          \
        do_printk("[DEBUG (%t)]: " fmt,                                   \
                  current_timestamp(),                                           \
                  ##__VA_ARGS__);                                              \
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

int
printk_print_buffer(void *state, size_t len, char *buffer);

// "windowed" printk
ssize_t
vswprintk(
        char *buf,
        size_t offset,
        size_t *size,
        const char *fmt,
        va_list *args); 
ssize_t
swprintk(
        char *buf,
        size_t offset,
        size_t *size,
        const char *fmt,
        ...);

// Alias for "swprintk(buf, 0, &buf_size, fmt, ...)"
ssize_t
snprintk(char *buf, size_t buf_size, const char *fmt, ...);

struct vprintk_state;

int
vprintk(
        struct vprintk_state *state,
        const char *fmt,
        va_list *args);

#endif
