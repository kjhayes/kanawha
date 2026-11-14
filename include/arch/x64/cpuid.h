#ifndef __KANAWHA__ARCH_X64_CPUID_H__
#define __KANAWHA__ARCH_X64_CPUID_H__

#include <kanawha/errno.h>
#include <kanawha/printk.h>

#define CPUID_VENDOR_ID_STRING 0x0

struct __packed x64_cpuid
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
};

// 0 -> cpuid not supported, else cpuid support is detected
int
x64_cpuid_supported(void);

int
x64_cpuid_ext(
        uint32_t eax,
        uint32_t ecx,
        struct x64_cpuid *id);

static inline int
x64_cpuid(
        uint32_t eax,
        struct x64_cpuid *id)
{
    return x64_cpuid_ext(eax, 0, id);
}

#endif
