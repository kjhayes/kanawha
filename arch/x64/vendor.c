
#include <arch/x64/vendor.h>
#include <arch/x64/cpuid.h>
#include <kanawha/string.h>
#include <kanawha/init.h>

#define X64_VENDOR_STRING_LENGTH 13

static x64_vendor_t vendor = X64_VENDOR_UNKNOWN;

static int
x64_cpuid_get_vendor_string(char str[X64_VENDOR_STRING_LENGTH])
{
    if(!x64_cpuid_supported()) {
        return -ENXIO;
    }

    struct x64_cpuid_result result;
    x64_cpuid(CPUID_VENDOR_ID_STRING, &result);

    ((uint32_t*)str)[0] = result.ebx;
    ((uint32_t*)str)[1] = result.edx;
    ((uint32_t*)str)[2] = result.ecx;

    str[12] = '\0';
    return 0;
}

x64_vendor_t
x64_get_vendor(void)
{
    if(vendor != X64_VENDOR_UNKNOWN) {
        return vendor;
    }
    char str[X64_VENDOR_STRING_LENGTH];
    x64_cpuid_get_vendor_string(str);

    if(0) {}
#define CHECK_VENDOR_STRING(__NAME, __STR, ...)\
    else if(strcmp(__STR, str) == 0) {\
        vendor = X64_VENDOR_ ## __NAME;\
    } 
    X64_VENDOR_XLIST(CHECK_VENDOR_STRING)
#undef CHECK_VENDOR_STRING

    return vendor;
}

const char *
x64_vendor_string(x64_vendor_t vendor) {
    switch(vendor) {
#define VENDOR_STRING_CASE(__NAME, __STR, ...)\
        case X64_VENDOR_ ## __NAME: \
            return __STR;
        X64_VENDOR_XLIST(VENDOR_STRING_CASE)
#undef VENDOR_STRING_CASE
        default:
            return "Invalid";
    }
}

static int
log_vendor_string(void) {
    x64_vendor_t vendor = x64_get_vendor();
    printk("Detected x86_64 Vendor: %s\n",
            x64_vendor_string(vendor));
    return 0;
}
declare_init_desc(static, log_vendor_string, "Checking x64 Vendor");

