#ifndef __KANAWHA__X64_MSR_H__
#define __KANAWHA__X64_MSR_H__

#include <kanawha/stdint.h>

#define X64_MSR_EFER (uint32_t)0xC0000080
#define X64_EFER_SCE (uint64_t)(1ULL<<0)
#define X64_EFER_LME (uint64_t)(1ULL<<8)
#define X64_EFER_LMA (uint64_t)(1ULL<<10)
#define X64_EFER_NXE (uint64_t)(1ULL<<11)

#define X64_MSR_FSBASE        (uint32_t)0xC0000100
#define X64_MSR_GSBASE        (uint32_t)0xC0000101
#define X64_MSR_KERNEL_GSBASE (uint32_t)0xC0000102

// syscall MSR(s)
#define X64_MSR_STAR   (uint32_t)0xC0000081
#define X64_MSR_LSTAR  (uint32_t)0xC0000082
#define X64_MSR_CSTAR  (uint32_t)0xC0000083
#define X64_MSR_SFMASK (uint32_t)0xC0000084

static inline
uint64_t read_msr(uint32_t msr)
{
    uint32_t low;
    uint32_t high;
    asm volatile("rdmsr" : "=a" (low), "=d" (high) : "c" (msr));
    return (((uint64_t)high) << 32) | (uint64_t)low;
}

static inline
void write_msr(uint32_t msr, uint64_t val)
{
    uint32_t low = val&0xFFFFFFFF;
    uint32_t high = (val>>32)&0XFFFFFFFF;
    asm volatile("wrmsr" :: "a" (low), "d" (high), "c" (msr));
}

#endif
