#ifndef __KANAWHA_ARCH_RISCV64__CSR_H__
#define __KANAWHA_ARCH_RISCV64__CSR_H__

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

#endif
