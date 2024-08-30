
#include <kanawha/init.h>
#include <kanawha/xcall.h>
#include <kanawha/cpu.h>
#include <kanawha/irq_domain.h>
#include <arch/x64/lapic.h>
#include <arch/x64/cpu.h>

#define X64_XCALL_VECTOR 0x47

static int
x64_setup_xcalls(void)
{
    int num_failures = 0;
    for(cpu_id_t id = 0; id < total_num_cpus(); id++) {
        struct cpu *gen_cpu = cpu_from_id(id);
        if(gen_cpu == NULL) {
            wprintk("Cannot find struct cpu for CPU %ld (total_num_cpus=%ld)!\n",
                    (sl_t)id, (sl_t)total_num_cpus());
            num_failures++;
            continue;
        }
        struct x64_cpu *cpu = container_of(gen_cpu, struct x64_cpu, cpu);
        struct lapic *apic = &cpu->apic;

        irq_t irq = irq_domain_revmap(apic->irq_domain, X64_XCALL_VECTOR);
        if(irq == NULL_IRQ) {
            wprintk("Cannot get X-Call Vector 0x%x for CPU %ld\n",
                    (u_t)X64_XCALL_VECTOR, (sl_t)id);
            num_failures++;
            continue;
        }
        
        int res = xcall_provide_ipi_irq(id, irq);
        if(res) {
            eprintk("Failed to provide X-Call vector 0x%x for CPU %ld! (err=%s)\n",
                    (u_t)X64_XCALL_VECTOR, (sl_t)id, errnostr(res));
            num_failures++;
            continue;
        }
    }

    if(num_failures > 0) {
        return -EINVAL;
    }
    return 0;
}
declare_init(smp_bringup, x64_setup_xcalls);

