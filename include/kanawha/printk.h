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
        nsec_t time_ns = time_to_nsec(current_timestamp());                    \
        unsigned long __printk__sec = time_ns / NSEC_PER_SEC;                  \
        unsigned long __printk__sec_dec =                                      \
            ((time_ns % NSEC_PER_SEC) * 10) / NSEC_PER_SEC;                    \
        do_printk("[%lu.%lu]: " fmt,                                           \
                  __printk__sec,                                               \
                  __printk__sec_dec,                                           \
                  ##__VA_ARGS__);                                              \
    } while(0)

#define eprintk(fmt, ...)                                                      \
    do                                                                         \
    {                                                                          \
        nsec_t time_ns = time_to_nsec(current_timestamp());                    \
        unsigned long __printk__sec = time_ns / NSEC_PER_SEC;                  \
        unsigned long __printk__sec_dec =                                      \
            ((time_ns % NSEC_PER_SEC) * 10) / NSEC_PER_SEC;                    \
        do_printk("[ERROR (%lu.%lu)]: " fmt,                                   \
                  __printk__sec,                                               \
                  __printk__sec_dec,                                           \
                  ##__VA_ARGS__);                                              \
    } while(0)

#define wprintk(fmt, ...)                                                      \
    do                                                                         \
    {                                                                          \
        nsec_t time_ns = time_to_nsec(current_timestamp());                    \
        unsigned long __printk__sec = time_ns / NSEC_PER_SEC;                  \
        unsigned long __printk__sec_dec =                                      \
            ((time_ns % NSEC_PER_SEC) * 10) / NSEC_PER_SEC;                    \
        do_printk("[WARN (%lu.%lu)]: " fmt,                                    \
                  __printk__sec,                                               \
                  __printk__sec_dec,                                           \
                  ##__VA_ARGS__);                                              \
    } while(0)

#ifdef DEBUG
#define dprintk(fmt, ...)                                                      \
    do                                                                         \
    {                                                                          \
        nsec_t time_ns = time_to_nsec(current_timestamp());                    \
        unsigned long __printk__sec = time_ns / NSEC_PER_SEC;                  \
        unsigned long __printk__sec_dec =                                      \
            ((time_ns % NSEC_PER_SEC) * 10) / NSEC_PER_SEC;                    \
        do_printk("[DEBUG (%lu.%lu)]: " fmt,                                   \
                  __printk__sec,                                               \
                  __printk__sec_dec,                                           \
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

int
snprintk(char *buf, size_t buf_size, const char *fmt, ...);

struct vprintk_state
{
    // Inputs
    const char *fmt_iter;
    va_list *args_ptr;

    // State
    int escaped;
    size_t buffer_head;

    int uppercase_hex;
    int size_modifier;
    int leading_zeros;
    int digits_specifier;

    // Constants
    void *state;
    int (*print_buffer)(void *state, size_t len, char *buf);
    size_t buffer_size;
    char *buffer;
};
int
vprintk(struct vprintk_state *state, const char *fmt, va_list *args);

#endif
