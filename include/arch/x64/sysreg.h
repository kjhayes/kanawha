#ifndef __KANAWHA__X64_SYSREG_H__
#define __KANAWHA__X64_SYSREG_H__

#include <kanawha/types.h>

static inline
uint32_t read_cr0(void) {
    uint64_t val;
    asm volatile ("mov %%cr0, %0" : "=r" (val));
    return (uint32_t)val;
}

static inline
void write_cr0(uint32_t val) {
    uint64_t real_val = (uint64_t)val;
    asm volatile ("mov %0, %%cr0" :: "r" (real_val));
}

static inline
uint64_t read_cr2(void) {
    uint64_t val;
    asm volatile ("mov %%cr2, %0" : "=r" (val));
    return (uint64_t)val;
}

static inline
uint64_t read_cr3(void) {
    uint64_t val;
    asm volatile ("mov %%cr3, %0" : "=r" (val));
    return val;
}

static inline
void write_cr3(uint64_t val) {
    asm volatile ("mov %0, %%cr3" :: "r" (val));
}

static inline
uint64_t read_cr4(void) {
    uint64_t val;
    asm volatile ("mov %%cr4, %0" : "=r" (val));
    return val;
}

static inline
void write_cr4(uint64_t val) {
    asm volatile ("mov %0, %%cr4" :: "r" (val));
}

#define X64_RFLAGS_XLIST(X)\
X(CF,   0,  1, "Carry")\
X(PF,   2,  1, "Parity")\
X(AF,   4,  1, "Auxiliary Carry")\
X(ZF,   6,  1, "Zero")\
X(SF,   7,  1, "Sign")\
X(TF,   8,  1, "Trap")\
X(IF,   9,  1, "Interrupt Enable")\
X(DF,   10, 1, "Direction")\
X(OF,   11, 1, "Overflow")\
X(IOPL, 12, 2, "IO Privilege Level")\
X(NT,   14, 1, "Nested Task")\
X(MD,   15, 1, "Mode")\
X(RF,   16, 1, "Resume")\
X(VM,   17, 1, "Virtual 8086")\
X(AC,   18, 1, "Alignment Check")\
X(VIF,  19, 1, "Virtual Interrupt Enable")\
X(VIP,  20, 1, "Virtual Interrupt Pending")\
X(ID,   21, 1, "CPUID")\
X(AES,  30, 1, "AES")\
X(AI,   31, 1, "Alt ISA")\

#define DEFINE_RFLAGS_CONSTANTS(__abbr, __shift, __bits, ...)\
static const uint64_t X64_RFLAGS_ ## __abbr ## _MASK = ((1ULL<<__bits)-1) << __shift;
X64_RFLAGS_XLIST(DEFINE_RFLAGS_CONSTANTS)

#undef DEFINE_RFLAGS_CONSTANTS
#undef X64_RFLAGS_XLIST

static inline
uint64_t read_rflags(void) {
    uint64_t val;
    asm volatile (
            "subq $128, %%rsp;"
            "pushfq;"
            "popq %0;"
            "addq $128, %%rsp;"
            : "=r" (val) :: "memory");
    return val;
}

#define  MXCSR_INVALID_OP_FLAG      (1ULL<<0)
#define  MXCSR_DENORMAL_FLAG        (1ULL<<1)
#define  MXCSR_DIV_BY_ZERO_FLAG     (1ULL<<2)
#define  MXCSR_OVERFLOW_FLAG        (1ULL<<3)
#define  MXCSR_UNDERFLOW_FLAG       (1ULL<<4)
#define  MXCSR_PRECISION_FLAG       (1ULL<<5)
#define  MXCSR_DENORMALS_ARE_ZEROS  (1ULL<<6)
#define  MXCSR_INVALID_OP_MASK      (1ULL<<7)
#define  MXCSR_DENORMAL_OP_MASK     (1ULL<<8)
#define  MXCSR_DIV_BY_ZERO_MASK     (1ULL<<9)
#define  MXCSR_OVERFLOW_MASK        (1ULL<<10)
#define  MXCSR_UNDERFLOW_MASK       (1ULL<<11)
#define  MXCSR_PRECISION_MASK       (1ULL<<12)
#define  MXCSR_ROUNDING_CONTROL     (1ULL<<13)
#define  MXCSR_FLUSH_TO_ZERO        (1ULL<<15)

static inline void
write_mxcsr(uint32_t value) {
    asm volatile ("ldmxcsr %0" : "=m" (value)); 
}

static inline uint32_t
read_mxcsr(void) {
    uint32_t value;
    asm volatile ("stmxcsr %0" : "=m" (value)); 
    return value;
}

#endif
