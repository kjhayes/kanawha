#ifndef __KANAWHA__ARCH_H__
#define __KANAWHA__ARCH_H__

#include <kanawha/errno.h>
#include <kanawha/stdint.h>
#include <kanawha/init.h>

/*
 * Generic "architecture" description enums
 */

typedef enum arch {
    ARCH_UNKNOWN = 0,
    ARCH_X86, // 32-bit
    ARCH_X64, // 64-bit
} arch_t;

typedef enum endian {
    ENDIAN_UNKNOWN = 0,
    ENDIAN_LITTLE,
    ENDIAN_BIG,
    ENDIAN_MIXED,
} endian_t;

#ifdef CONFIG_X64
#include <arch/x64/arch.h>
#endif

#ifndef KERNEL_ARCH
#error "Architecture did not define KERNEL_ARCH enum!"
#else
const static arch_t kernel_arch = KERNEL_ARCH;
#undef KERNEL_ARCH
#endif

#ifndef KERNEL_ENDIANNESS
static endian_t kernel_endian = ENDIAN_UNKNOWN;
static int
detect_kernel_endianness(void) {
    uint16_t val = 0x1234;
    uint8_t *val_ptr = (uint8_t*)&val;
    uint8_t first_byte = *val_ptr;

    if(first_byte == 0x34) {
        kernel_endian = ENDIAN_LITTLE;
    } else if(first_byte == 0x12) {
        kernel_endian = ENDIAN_BIG;
    } else {
        kernel_endian = ENDIAN_UNKNOWN;
        return -EINVAL;
    }
    return 0;
}
declare_init_desc(static, detect_kernel_endianness, "Detecting Kernel Endianness");
#else
const static endian_t kernel_endian = KERNEL_ENDIANNESS;
#undef KENREL_ENDIANNESS
#endif

#endif
