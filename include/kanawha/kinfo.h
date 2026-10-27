#ifndef __KANAWHA__INFO_H__
#define __KANAWHA__INFO_H__

#include <kanawha/registry.h>
#include <kanawha/sysfs/vfs.h>
#include <kanawha/init.h>
#include <kanawha/printer.h>

struct kinfo;

typedef void(kinfo_callback_f)(
        struct kinfo *info,
        struct printer *p);

struct kinfo *
kinfo_create(
        const char *name,
        kinfo_callback_f *callback);

int
kinfo_destroy(
        struct kinfo *info);

const char *
kinfo_get_name(
        struct kinfo *info);


#define declare_kinfo_callback(__NAME, __CALLBACK)\
static struct kinfo *__kinfo_##__NAME = NULL; \
static int \
__register_kinfo_##__NAME(void) { \
    __kinfo_##__NAME = \
        kinfo_create(#__NAME, \
                 __CALLBACK); \
    if(__kinfo_##__NAME == NULL) { \
        return -EINVAL; \
    } \
    return 0; \
} \
declare_init(late, __register_kinfo_##__NAME);

#define declare_kinfo(__NAME, __FMT, ...)\
static void \
__kinfo_##__NAME##_callback( \
        struct kinfo *__kinfo,\
        struct printer *__printer) \
{ \
    fmt_print(__printer, __FMT, ##__VA_ARGS__); \
} \
declare_kinfo_callback( \
        __NAME, \
        __kinfo_##__NAME##_callback); \

#endif
