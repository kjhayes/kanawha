
#include <arch/riscv64/csr.h>
#include <kanawha/assert.h>

int
riscv64_enable_fpu(void)
{
    uint64_t value = read_csr(sstatus);
    value |= (0b11 << 13);
    write_csr(sstatus, value);
    DEBUG_ASSERT(read_csr(sstatus) & (0b11<<13));
    return 0;
}

