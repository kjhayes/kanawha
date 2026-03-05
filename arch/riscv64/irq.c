
#include <arch/riscv64/csr.h>
#include <kanawha/irq.h>
#include <kanawha/types.h>

int
arch_irq_disable(void)
{
    write_csr(sstatus, read_csr(sstatus) & ~(1ULL << 1));
    return 0;
}

int
arch_irq_enable(void)
{
    write_csr(sstatus, read_csr(sstatus) | (1ULL << 1));
    return 0;
}

int
arch_irqs_enabled(void)
{
    uint64_t status = read_csr(sstatus);
    return status & (1ULL << 1);
}
