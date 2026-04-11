
#include <kanawha/percpu.h>

int
arch_set_percpu_area_remote(cpu_id_t remote_id, void *percpu_area)
{
    return -EUNIMPL;
}

int
arch_set_percpu_area(cpu_id_t cur_cpu_id, void *percpu_area)
{
    return -EUNIMPL;
}
