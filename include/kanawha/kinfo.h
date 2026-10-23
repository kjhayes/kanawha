#ifndef __KANAWHA__INFO_H__
#define __KANAWHA__INFO_H__

#include <kanawha/registry.h>
#include <kanawha/sysfs/vfs.h>
#include <kanawha/init.h>

struct kinfo;
struct kinfo_printer_state;

typedef void(kinfo_printer_f)(
        struct kinfo_printer_state *state,
        const char *fmt,
        ...);

typedef void(kinfo_callback_f)(
        kinfo_printer_f *printer,
        struct kinfo_printer_state *pstate,
        void *state);

struct kinfo *
kinfo_create(
        const char *name,
        kinfo_callback_f *callback,
        void *state);

int
kinfo_destroy(
        struct kinfo *info);

const char *
kinfo_get_name(
        struct kinfo *info);


#define declare_kinfo_callback(__NAME, __CALLBACK, __PTR)\
static struct kinfo *__kinfo_##__NAME = NULL; \
static int \
__register_kinfo_##__NAME(void) { \
    __kinfo_##__NAME = \
        kinfo_create(#__NAME, \
                 __CALLBACK, \
                 __PTR); \
    if(__kinfo_##__NAME == NULL) { \
        return -EINVAL; \
    } \
    return 0; \
} \
declare_init(late, __register_kinfo_##__NAME);

#define declare_kinfo(__NAME, __FMT, ...)\
static void \
__kinfo_##__NAME##_callback( \
        kinfo_printer_f *__printer, \
        struct kinfo_printer_state *__pstate, \
        void *__null_state) \
{ \
    (*__printer)(__pstate, __FMT, ##__VA_ARGS__); \
} \
declare_kinfo_callback( \
        __NAME, \
        __kinfo_##__NAME##_callback, \
        NULL); \

#endif
