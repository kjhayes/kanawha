
#include <arch/riscv64/csr.h>
#include <kanawha/errno.h>
#include <kanawha/percpu.h>
#include <kanawha/types.h>

struct riscv64_percpu_state __riscv64_percpu_data[CONFIG_MAX_CPUS] = {0};

extern int __builtin_kpercpu_start[];

int
arch_set_percpu_area_remote(cpu_id_t remote_id, void *percpu_area)
{
    if(remote_id >= CONFIG_MAX_CPUS)
    {
        return -EINVAL;
    }
    uintptr_t offset =
        (uintptr_t)percpu_area - (uintptr_t)__builtin_kpercpu_start;
    __riscv64_percpu_data[remote_id].percpu_offset = offset;
    return 0;
}

int
arch_set_percpu_area(cpu_id_t cur_cpu_id, void *percpu_area)
{
    if(cur_cpu_id >= CONFIG_MAX_CPUS)
    {
        eprintk("arch_set_percpu_area cannot set cpu_id=%lu > "
                "CONFIG_MAX_CPUS=%lu\n",
                (ul_t)cur_cpu_id,
                (ul_t)CONFIG_MAX_CPUS);
        return -EINVAL;
    }
    uintptr_t offset =
        (uintptr_t)percpu_area - (uintptr_t)__builtin_kpercpu_start;
    __riscv64_percpu_data[cur_cpu_id].percpu_offset = offset;
    uint64_t tp_value = ((uint64_t)&__riscv64_percpu_data[cur_cpu_id]);
    asm volatile("mv tp, %0" ::"r"(tp_value));
    write_csr(sscratch, tp_value);
    return 0;
}
