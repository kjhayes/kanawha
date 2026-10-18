
#include <kanawha/syscall.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

//static inline uint64_t __attribute__((always_inline))
//rdtsc (void)
//{
//    uint32_t lo, hi;
//    __asm__ ("rdtsc" : "=a"(lo), "=d"(hi));
//    return lo | ((uint64_t)(hi) << 32);
//}

int main(int argc, const char **argv)
{
    size_t runs = 0;

//    asm("rdtsc;\n"
//        "movq %rax, %rdi;\n"
//        "movq %rdx, %rsi;\n"
//        "int $9;\n"
//        );
    printf("Returned from exception (unexpected)!\n");

    return 0;
}
// 
// __attribute__((used))
// void print_func(uint32_t before_rax, uint32_t before_rdx, uint32_t after_rax, uint32_t after_rdx)
// {
//     uint64_t before_cycles = before_rax | ((uint64_t)before_rdx << 32);
//     uint64_t after_cycles = after_rax | ((uint64_t)after_rdx << 32);
//     uint64_t total_cycles = after_cycles - before_cycles;
//     printf("FAULTED TO USERSPACE! (cycles=%lu)\n", total_cycles);
//     exit(1);
// }
// 
// __attribute__((used))
// __attribute__((naked))
// void fault_func(void)
// {
// asm (
// "    rdtsc;\n"
// "    movq %rdx, %rcx;\n"
// "    movq %rax, %rdx;\n"
// "    andq $(~0xF), %rsp;\n"
// "    jmp print_func;\n"
// );
// }


