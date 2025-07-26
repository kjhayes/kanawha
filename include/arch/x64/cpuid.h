#ifndef __KANAWHA__ARCH_X64_CPUID_H__
#define __KANAWHA__ARCH_X64_CPUID_H__

#include <kanawha/errno.h>
#include <kanawha/printk.h>

#define CPUID_VENDOR_ID_STRING 0x0
#define CPUID_GETFEATURES      0x1

struct __packed x64_cpuid_result {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
};

// 0 -> cpuid not supported, else cpuid support is detected
extern int
x64_cpuid_supported(void);

extern void
x64_cpuid(uint32_t eax, struct x64_cpuid_result *result);

static inline uint64_t
x64_cpuid_features(void) {
    struct x64_cpuid_result result;
    x64_cpuid(CPUID_GETFEATURES, &result);
    uint64_t feat = (uint64_t)result.ecx | ((uint64_t)result.edx << 32);
    return feat;
}

#endif
