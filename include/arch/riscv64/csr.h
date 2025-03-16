#ifndef __KANAWHA_ARCH_RISCV64__CSR_H__
#define __KANAWHA_ARCH_RISCV64__CSR_H__

#include <kanawha/time.h>

#define read_csr(__csr)\
    ({\
      uint64_t val;\
      asm volatile("csrr %0, " #__csr \
              : "=r" (val));\
      val;\
     })
#define write_csr(__csr, __val)\
    do {\
      asm volatile("csrw " #__csr ", %0"\
              :: "r" (__val));\
    } while(0)

#define SSTATUS_MASK_SIE  (0b1ULL<<1)
#define SSTATUS_MASK_SPIE (0b1ULL<<5)
#define SSTATUS_MASK_UBE  (0b1ULL<<6)
#define SSTATUS_MASK_SPP  (0b1ULL<<8)
#define SSTATUS_MASK_VS   (0b11ULL<<9)
#define SSTATUS_MASK_FS   (0b11ULL<<13)
#define SSTATUS_MASK_XS   (0b11ULL<<15)
#define SSTATUS_MASK_SUM  (0b1ULL<<18)
#define SSTATUS_MASK_MXR  (0b1ULL<<19)
#define SSTATUS_MASK_UXL  (0b11ULL<<32)
#define SSTATUS_MASK_SD   (0b1ULL<<63)

static inline cycles_t
riscv64_rdtime(void)
{
    uint64_t value;
    asm volatile ("rdtime %0" : "=r" (value));
    return (cycles_t)value;
}

static inline cycles_t
riscv64_rdcycle(void)
{
    uint64_t value;
    asm volatile ("rdcycle %0" : "=r" (value));
    return (cycles_t)value;
}

#endif
