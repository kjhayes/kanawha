#ifndef __KANAWHA__ARM64_PERCPU_H__
#define __KANAWHA__ARM64_PERCPU_H__

#include <kanawha/types.h>
#include <arch/arm64/sysreg.h>

struct arm64_percpu_data {
    uintptr_t percpu_offset;
};

extern struct arm64_percpu_data __arm64_percpu_data[CONFIG_MAX_CPUS];

#define __arch_percpu_ptr(ptr) \
    ({\
     struct arm64_percpu_data *data = (void*)arm64_sysreg_readq(TPIDR_EL1);\
     void *global_ptr = ((void*)ptr) + data->percpu_offset;\
     (typeof(ptr))global_ptr;\
     })
#define __arch_percpu_ptr_specific(ptr, cpu_id) \
    ({\
     struct arm64_percpu_data *data = &__arm64_percpu_data[cpu_id];\
     void *global_ptr = ((void*)ptr) + data->percpu_offset;\
     (typeof(ptr))global_ptr;\
     })

#endif
