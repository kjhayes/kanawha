
#include <kanawha/init.h>
#include <kanawha/page_alloc.h>
#include <kanawha/string.h>
#include <kanawha/thread.h>
#include <kanawha/cpu.h>
#include <kanawha/mem_flags.h>
#include <arch/riscv64/sbi.h>
#include <arch/riscv64/sbi_hsm.h>
#include <arch/riscv64/mmu.h>
#include <kanawha/attribute.h>

#if CONFIG_MAX_CPUS > 1

struct riscv64_ap_trampoline {
    void *stack;

    cpu_id_t cpu_id;
    uint64_t done;
};

#define AP_BRINGUP_STACK_ORDER 12

static struct riscv64_ap_trampoline ap_bringup_trampoline = { 0 };

__attribute__((aligned(4096)))
static uint8_t ap_bringup_virtual_stack[1ULL<<AP_BRINGUP_STACK_ORDER];

_Static_assert(sizeof(ap_bringup_virtual_stack) == 1ULL<<AP_BRINGUP_STACK_ORDER, "ap_bringup_stack has incorrect size!");

void *
riscv64_boot_ap_init(
        hartid_t hartid)
{
    int res;

    struct riscv64_ap_trampoline *trampoline = &ap_bringup_trampoline;

    // All we really need to do is move the stack into high-mem

    return trampoline->stack;
}

__noreturn
void
riscv64_virtual_ap_init(void)
{
    int res;

    struct riscv64_ap_trampoline *trampoline = &ap_bringup_trampoline;

    cpu_id_t self = trampoline->cpu_id;

    // Enable the default vmem_map so we can access the heap
    struct vmem_map *default_map = vmem_get_default_map();
    arch_vmem_map_activate(default_map);

    // Enable percpu variables
    struct cpu *cpu = cpu_from_id(self);
    arch_set_percpu_area(self, cpu->percpu_data);
    set_current_cpu_id(self);

    res=  vmem_percpu_init();
    if(res) {
        eprintk("AP(%ld) vmem_percpu_init Failed! (err=%s)\n",
                (sl_t)self, errnostr(res));
        panic("riscv64_boot_ap_init failed!\n");
    }

    printk("Starting Threading on CPU (%ld)\n",
            (sl_t)current_cpu_id());

    extern void riscv64_ap_init(void *__trampoline);
    cpu_start_threading(riscv64_ap_init, (void*)trampoline);

    panic("Trying to return from riscv64_boot_ap_init!\n");
}

void
riscv64_ap_init(void *__trampoline) {
    // Let the BSP continue bringing up more AP(s) or continue on itself
    struct riscv64_ap_trampoline *trampoline = &ap_bringup_trampoline;
    trampoline->done = 1;

    printk("CPU (%ld) init thread is idling\n", (sl_t)current_cpu_id());
    idle_loop();

    panic("Returned from idle thread!\n");
}

extern void riscv64_ap_entry(void *, void*);
static void __phys * volatile riscv64_ap_entry_ptr = (void __phys *)&riscv64_ap_entry;

static int
riscv64_smp_bringup_aps(void)
{
    int res;

    struct vmem_map *map = vmem_map_create();
    if(map == NULL) {
        eprintk("Failed to create vmem_map for bringing up AP(s)!\n");
        return -ENOMEM;
    }

    struct vmem_region *lowmem_identity_map =
        vmem_region_create_direct(
                0,
                1ULL<<CONFIG_RISCV64_IDENTITY_MAP_ORDER,
                VMEM_REGION_READ|VMEM_REGION_WRITE|VMEM_REGION_EXEC);

    if(lowmem_identity_map == NULL) {
        eprintk("Failed to create lowmem identity map region for bringing up AP(s)!\n");
        vmem_map_destroy(map);
        return -ENOMEM;
    }

    res = vmem_map_map_region(map, lowmem_identity_map, 0x0);
    if(res) {
        eprintk("Failed to map lowmem identity region into vmem_map for bringing up AP(s)!\n");
        vmem_map_destroy(map);
        vmem_region_destroy(lowmem_identity_map);
        return res;
    }

    struct vmem_region *highmem_map =
        vmem_region_create_direct(
                arch_kernel_phys_start(),
                (arch_kernel_phys_size() + 0xFFFULL) & ~0xFFFULL,
                VMEM_REGION_READ|VMEM_REGION_WRITE|VMEM_REGION_EXEC);

    if(highmem_map == NULL) {
        eprintk("Failed to create highmem region for bringing up AP(s)!\n");
        vmem_map_destroy(map);
        vmem_region_destroy(lowmem_identity_map);
        return -ENOMEM;
    }

    res = vmem_map_map_region(map, highmem_map, (void*)CONFIG_RISCV64_KERNEL_VIRTUAL_BASE);
    if(res) {
        eprintk("Failed to map highmem region into vmem_map for bringing up AP(s)!\n");
        vmem_map_destroy(map);
        vmem_region_destroy(lowmem_identity_map);
        vmem_region_destroy(highmem_map);
        return res;
    }

    arch_dump_vmem_map(do_printk, map);

    for(cpu_id_t id = 0; id < total_num_cpus(); id++)
    {
        struct riscv64_ap_trampoline *trampoline = &ap_bringup_trampoline;

        hartid_t hartid = cpu_id_to_hartid(id);
        if(hartid == current_hartid()) {
            continue;
        }

        trampoline->done = 0;
        trampoline->cpu_id = id;
        trampoline->stack = ((void*)ap_bringup_virtual_stack) + (1ULL<<AP_BRINGUP_STACK_ORDER);

        uint64_t satp = riscv64_format_satp(map->arch_state.root_table, map->arch_state.root_level);

        int status = sbi_hart_get_status(hartid);
        if(status == SBI_HART_STATE_STOPPED) {
            res = sbi_hart_start(
                    hartid,
                    riscv64_ap_entry_ptr,
                    satp); 
            if(res) {
                eprintk("Failed to start AP(%lu)! (err=%s)\n",
                        (ul_t)id,
                        errnostr(res));
                return res;
            }
            printk("Started AP(%lu)!\n",
                    (ul_t)id);

            while(!trampoline->done) {
                // Spin waiting on the other core
            }
        }
    }

    res = vmem_map_destroy(map);
    if(res) {
        wprintk("Failed to free AP bringup vmem_map! (Leaking Memory)\n");
    }
    res = vmem_region_destroy(lowmem_identity_map);
    if(res) {
        wprintk("Failed to free AP bringup lowmem vmem_region! (Leaking Memory)\n");
    }
    res = vmem_region_destroy(highmem_map);
    if(res) {
        wprintk("Faield to free AP bringup highmem vmem_region! (Leaking Memory)\n");
    }
    return 0;
}
declare_init_desc(smp_bringup, riscv64_smp_bringup_aps, "Bringing Up AP(s)");

#endif

