
#include <kanawha/percpu.h>
#include <arch/arm64/sysreg.h>

struct arm64_percpu_data __arm64_percpu_data[CONFIG_MAX_CPUS] = {0};

extern int __builtin_kpercpu_start[];

int
arch_set_percpu_area_remote(cpu_id_t remote_id, void *percpu_area)
{
    struct arm64_percpu_data *data = &__arm64_percpu_data[remote_id];
    printk("arch_set_percpu_area_remote: cpu_id=%ld, area=%p, data=%p\n", (sl_t)remote_id, percpu_area, data);
    data->percpu_offset = (uintptr_t)percpu_area - (uintptr_t)__builtin_kpercpu_start;
    return 0;
}

int
arch_set_percpu_area(cpu_id_t cur_cpu_id, void *percpu_area)
{
    struct arm64_percpu_data *data = &__arm64_percpu_data[cur_cpu_id];
    printk("arch_set_percpu_area: cur_cpu_id=%ld, area=%p, data=%p\n", (sl_t)cur_cpu_id, percpu_area, data);
    data->percpu_offset = (uintptr_t)percpu_area - (uintptr_t)__builtin_kpercpu_start;
    arm64_sysreg_writeq(TPIDR_EL1, (uintptr_t)(void*)data);
    printk("arch_set_percpu_area: set area to %p\n", percpu_ptr(__builtin_kpercpu_start));
    return 0;
}
