
#include <kanawha/kuser.h>
#include <kanawha/attribute.h>
#include <kanawha/types.h>
#include <kanawha/init.h>
#include <kanawha/errno.h>
#include <kanawha/mem_flags.h>
#include <kanawha/vmem.h>

extern int __kuser_virt_start[];
extern int __kuser_virt_end[];
static inline void __kuser *
kuser_virt_start(void) {
    return (void __kuser *)__kuser_virt_start;
}
static inline void __kuser *
kuser_virt_end(void) {
    return (void __kuser *)__kuser_virt_end;
}
static inline size_t
kuser_virt_size(void) {
    return kuser_virt_end() - kuser_virt_start();
}

extern int __kuser_text_virt_start[];
extern int __kuser_text_virt_end[];
static inline void __kuser *
kuser_text_virt_start(void) {
    return (void __kuser *)__kuser_text_virt_start;
}
static inline void __kuser *
kuser_text_virt_end(void) {
    return (void __kuser *)__kuser_text_virt_end;
}
static inline size_t
kuser_text_virt_size(void) {
    return kuser_text_virt_end() - kuser_text_virt_start();
}

extern int __kuser_data_virt_start[];
extern int __kuser_data_virt_end[];
static inline void __kuser *
kuser_data_virt_start(void) {
    return (void __kuser *)__kuser_data_virt_start;
}
static inline void __kuser *
kuser_data_virt_end(void) {
    return (void __kuser *)__kuser_data_virt_end;
}
static inline size_t
kuser_data_virt_size(void) {
    return kuser_data_virt_end() - kuser_data_virt_start();
}

extern int __kuser_rodata_virt_start[];
extern int __kuser_rodata_virt_end[];
static inline void __kuser *
kuser_rodata_virt_start(void) {
    return (void __kuser *)__kuser_rodata_virt_start;
}
static inline void __kuser *
kuser_rodata_virt_end(void) {
    return (void __kuser *)__kuser_rodata_virt_end;
}
static inline size_t
kuser_rodata_virt_size(void) {
    return kuser_rodata_virt_end() - kuser_rodata_virt_start();
}

// Physical Regions

extern int __kuser_phys_start[];
static inline void __phys *
kuser_phys_start(void) {
    return (void __phys *)__kuser_phys_start;
}
static inline size_t
kuser_phys_size(void) {
    return kuser_virt_size();
}

static inline void __phys *
kuser_text_phys_start(void) {
    return kuser_phys_start() + (kuser_text_virt_start() - kuser_virt_start());
}
static inline size_t
kuser_text_phys_size(void) {
    return kuser_text_virt_size();
}

static inline void __phys *
kuser_rodata_phys_start(void) {
    return kuser_phys_start() + (kuser_rodata_virt_start() - kuser_virt_start());
}
static inline size_t
kuser_rodata_phys_size(void) {
    return kuser_rodata_virt_size();
}

static inline void __phys *
kuser_data_phys_start(void) {
    return kuser_phys_start() + (kuser_data_virt_start() - kuser_virt_start());
}
static inline size_t
kuser_data_phys_size(void) {
    return kuser_data_virt_size();
}

// Reserving the virtual memory region
static int
kuser_reserve_virtual_memory(void)
{
    int res;
    struct mem_flags *pflags = get_phys_mem_flags();
    if(pflags == NULL) {
        return -EINVAL;
    }

    printk("kuser: Physical Memory Region [%p-%p)\n",
            kuser_phys_start(),
            kuser_phys_start() + kuser_phys_size());
    res = mem_flags_reserve_region(
            pflags,
            (uintptr_t)kuser_phys_start(),
            kuser_phys_size(),
            PHYS_MEM_FLAGS_RAM|PHYS_MEM_FLAGS_AVAIL,
            0,
            0,
            PHYS_MEM_FLAGS_AVAIL);
    if(res) {
        return res;
    }

    struct mem_flags *vflags = get_virt_mem_flags();
    if(vflags == NULL) {
        return -EINVAL;
    }

    printk("kuser: Virtual Memory Region [%p-%p)\n",
            kuser_virt_start(),
            kuser_virt_start() + kuser_virt_size());
    res = mem_flags_reserve_region(
            vflags,
            (uintptr_t)kuser_virt_start(),
            kuser_virt_size(),
            VIRT_MEM_FLAGS_AVAIL,
            0,
            VIRT_MEM_FLAGS_KUSER,
            VIRT_MEM_FLAGS_AVAIL);
    if(res) {
        eprintk("kuser: failed to reserve virtual memory region %e\n",
                res);
        return res;
    }

    res = mem_flags_check_region(
            vflags,
            (uintptr_t)kuser_text_virt_start(),
            kuser_text_virt_size(),
            VIRT_MEM_FLAGS_KUSER,
            VIRT_MEM_FLAGS_AVAIL);
    if(res) {
        eprintk("kuser: failed to reserve .text virtual memory region %e\n",
                res);
        return res;
    }

    res = mem_flags_check_region(
            vflags,
            (uintptr_t)kuser_data_virt_start(),
            kuser_data_virt_size(),
            VIRT_MEM_FLAGS_KUSER,
            VIRT_MEM_FLAGS_AVAIL);
    if(res) {
        eprintk("kuser: failed to reserve .data virtual memory region %e\n",
                res);
        return res;
    }

    res = mem_flags_check_region(
            vflags,
            (uintptr_t)kuser_rodata_virt_start(),
            kuser_rodata_virt_size(),
            VIRT_MEM_FLAGS_KUSER,
            VIRT_MEM_FLAGS_AVAIL);
    if(res) {
        eprintk("kuser: failed to reserve .rodata virtual memory region %e\n",
                res);
        return res;
    }

    return 0;
}
declare_init_desc(post_mem_flags, kuser_reserve_virtual_memory, "Reserving kuser Physical/Virtual Memory Region");

// Mapping the region
static struct vmem_region *kuser_text_region = NULL;
static struct vmem_region *kuser_data_region = NULL;
static struct vmem_region *kuser_rodata_region = NULL;
static int
kuser_init_vmem(void)
{
    int res;

    struct vmem_region *text = NULL;
    struct vmem_region *data = NULL;
    struct vmem_region *rodata = NULL;

    if(kuser_text_virt_size() > 0) {
        text = vmem_region_create_direct(
                kuser_text_phys_start(),
                kuser_text_phys_size(),
                VMEM_REGION_READ|VMEM_REGION_EXEC|VMEM_REGION_USER);
        if(text == NULL) {
            res = -ENOMEM;
            goto err;
        }
        kuser_text_region = text;
        res = vmem_force_mapping(
                kuser_text_region,
                (void *)kuser_text_virt_start());
        if(res) {
            goto err;
        }
    }

    if(kuser_rodata_virt_size() > 0) {
        rodata = vmem_region_create_direct(
                kuser_rodata_phys_start(),
                kuser_rodata_phys_size(),
                VMEM_REGION_READ|VMEM_REGION_USER);
        if(rodata == NULL) {
            res = -ENOMEM;
            goto err;
        }
        kuser_rodata_region = rodata;
        res = vmem_force_mapping(
                kuser_rodata_region,
                (void *)kuser_rodata_virt_start());
        if(res) {
            goto err;
        }
    }

    if(kuser_data_virt_size() > 0) {
        data = vmem_region_create_direct(
                kuser_data_phys_start(),
                kuser_data_phys_size(),
                VMEM_REGION_READ|VMEM_REGION_WRITE|VMEM_REGION_USER);
        if(text == NULL) {
            res = -ENOMEM;
            goto err;
        }
        kuser_data_region = data;
        res = vmem_force_mapping(
                kuser_data_region,
                (void *)kuser_data_virt_start());
        if(res) {
            goto err;
        }
    }

    return 0;
err:
    if(text != NULL) {
        kuser_text_region = NULL;
        vmem_region_destroy(text);
    }
    if(rodata != NULL) {
        kuser_rodata_region = NULL;
        vmem_region_destroy(rodata);
    }
    if(data != NULL) {
        kuser_data_region = NULL;
        vmem_region_destroy(data);
    }
    return res;
}
declare_init_desc(post_vmem, kuser_init_vmem, "Mapping kuser Virtual Memory Regions");

