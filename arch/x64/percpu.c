
#include <kanawha/percpu.h>
#include <kanawha/string.h>
#include <arch/x64/msr.h>
#include <arch/x64/percpu.h>

struct x64_percpu_data
__x64_percpu_data[CONFIG_MAX_CPUS] = { 0 };

extern int __builtin_kpercpu_start[];

int
arch_set_percpu_area_remote(cpu_id_t remote_id, void *percpu_area)
{
    __x64_percpu_data[remote_id].percpu_offset = percpu_area - (uintptr_t)__builtin_kpercpu_start;
    return 0;
}

int
arch_set_percpu_area(cpu_id_t cur_cpu_id, void *percpu_area)
{
    __x64_percpu_data[cur_cpu_id].percpu_offset = percpu_area - (uintptr_t)__builtin_kpercpu_start;
    write_msr(X64_MSR_GSBASE, (uint64_t)&__x64_percpu_data[cur_cpu_id]);
    return 0;
}

