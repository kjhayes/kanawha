#ifndef __KANAWHA_ARCH_RISCV64__SBI_H__
#define __KANAWHA_ARCH_RISCV64__SBI_H__

#include <kanawha/types.h>
#include <kanawha/errno.h>
#include <kanawha/attribute.h>

#define SBI_EXTID_BASE 0x10

#define SBI_SUCCESS               ( 0)
#define SBI_ERR_FAILED            (-1)
#define SBI_ERR_NOT_SUPPORTED     (-2)
#define SBI_ERR_INVALID_PARAM     (-3)
#define SBI_ERR_DENIED            (-4)
#define SBI_ERR_INVALID_ADDRESS   (-5)
#define SBI_ERR_ALREADY_AVAILABLE (-6)
#define SBI_ERR_ALREADY_STARTED   (-7)
#define SBI_ERR_ALREADY_STOPPED   (-8)


struct sbiret {
    long error;
    long value;
};

static inline int
sbiret_to_errno(struct sbiret *ret) {
    switch(ret->error) {
        case SBI_SUCCESS: return 0;
        case SBI_ERR_FAILED: return -EFAULT;
        case SBI_ERR_NOT_SUPPORTED: return -EUNIMPL;
        case SBI_ERR_INVALID_PARAM: return -EINVAL;
        case SBI_ERR_DENIED: return -EPERM;
        case SBI_ERR_INVALID_ADDRESS: return -EINVAL;
        case SBI_ERR_ALREADY_AVAILABLE: return -EALREADY;
        case SBI_ERR_ALREADY_STARTED: return -EALREADY;
        case SBI_ERR_ALREADY_STOPPED: return -EALREADY;
        default: return -EINVAL;
    }
}

static inline struct sbiret
sbi_ecall(
        uint64_t ext_id,
        uint64_t func_id,
        uint64_t a0,
        uint64_t a1,
        uint64_t a2,
        uint64_t a3,
        uint64_t a4,
        uint64_t a5)
{
    uint64_t err;
    uint64_t value;
    asm volatile (
            "mv a0, %2;"
            "mv a1, %3;"
            "mv a2, %4;"
            "mv a3, %5;"
            "mv a4, %6;"
            "mv a5, %7;"
            "mv a6, %8;"
            "mv a7, %9;"
            "ecall;"
            "mv %0, a0;"
            "mv %1, a1;"
            : "=r" (err),
              "=r" (value)
            : "r" (a0),
              "r" (a1),
              "r" (a2),
              "r" (a3),
              "r" (a4),
              "r" (a5),
              "r" (func_id),
              "r" (ext_id)
            : "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "memory"
            );
    struct sbiret ret = {
        .error = err,
        .value = value,
    };
    return ret;
}

// Returns 0 if the extension exists, negative errno if not
__maybe_unused
static int
sbi_probe_extension(
        long ext_id)
{
    struct sbiret ret;
    ret = sbi_ecall(
            SBI_EXTID_BASE,
            0x3,
            ext_id,
            0,
            0,
            0,
            0,
            0);

    if(ret.error != SBI_SUCCESS) {
        return sbiret_to_errno(&ret);
    }

    if(ret.value == 0) {
        return -ENXIO;
    } else {
        return 0;
    }
}

#endif
