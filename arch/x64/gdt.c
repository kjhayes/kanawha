
#include <arch/x64/gdt.h>
#include <kanawha/init.h>
#include <kanawha/stddef.h>
#include <kanawha/stdint.h>
#include <kanawha/cpu.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/thread.h>
#include <kanawha/xcall.h>
#include <kanawha/atomic.h>
#include <arch/x64/cpu.h>

__attribute__((used))
struct gdt64 x64_bsp_gdt64 = {
    .null = { 0 }, // Null
    .kernel_code = { // Kernel Code
        .limit_low_16 = 0xFFFF,
        .base_low_24 = 0x0,
        .accessed = 1,
        .read_write = 1,
        .conforming = 0,
        .executable = 1,
        .mb1 = 1,
        .ring = 0,
        .present = 1,
        .limit_middle_4 = 0xF,
        .avail = 0,
        .long_mode = 1,
        .sz_32 = 0,
        .granularity = 1,
        .base_high_8 = 0x0,
    }, 
    .kernel_data = { // Kernel Data
        .limit_low_16 = 0xFFFF,
        .base_low_24 = 0x0,
        .accessed = 1,
        .read_write = 1,
        .conforming = 0,
        .executable = 0,
        .mb1 = 1,
        .ring = 0,
        .present = 1,
        .limit_middle_4 = 0xF,
        .avail = 0,
        .long_mode = 0,
        .sz_32 = 1,
        .granularity = 1,
        .base_high_8 = 0x0,
    },
    .tss = {
        .limit_low_16 = X64_TSS_SEGMENT_SIZE & 0xFFFF,
        .base_low_24 = 0x0, // Some code will need to patch the TSS base at boot
                            // (This code will need to be modified if the layout of our GDT changes)
        .type = X64_GDT_SYSTEM_SEGMENT_TYPE_TSS,
        .mb0 = 0,
        .ring = 0,
        .present = 1,
        .limit_middle_4 = (X64_TSS_SEGMENT_SIZE>>16) & 0xF,
        .avail = 0,
        .__resv0_0 = 0,
        .granularity = 0,
        .base_high_40 = 0x0, // Needs to be patched
        .__resv0_1 = 0,
    }, 
    .user_data = { // User Data
        .limit_low_16 = 0xFFFF,
        .base_low_24 = 0x0,
        .accessed = 1,
        .read_write = 1,
        .conforming = 0,
        .executable = 0,
        .mb1 = 1,
        .ring = 3,
        .present = 1,
        .limit_middle_4 = 0xF,
        .avail = 0,
        .long_mode = 0,
        .sz_32 = 1,
        .granularity = 1,
        .base_high_8 = 0x0,
    },
    .user_code = { // User Code
        .limit_low_16 = 0xFFFF,
        .base_low_24 = 0x0,
        .accessed = 1,
        .read_write = 1,
        .conforming = 0,
        .executable = 1,
        .mb1 = 1,
        .ring = 3,
        .present = 1,
        .limit_middle_4 = 0xF,
        .avail = 0,
        .long_mode = 1,
        .sz_32 = 0,
        .granularity = 1,
        .base_high_8 = 0x0,
    },
};

__attribute__((used))
uint8_t x64_bsp_tss_data[X64_TSS_SEGMENT_SIZE] = { 0 };

void
x64_init_gdt_bsp(void) {
    // Once we are fully in long mode, we need to reload the GDT
    // using it's permanent virtual address
    struct gdt64_descriptor gdtr;
    gdtr.address = (uint64_t)&x64_bsp_gdt64;
    gdtr.limit = sizeof(struct gdt64);
    asm volatile ("lgdtq (%0)" :: "r" (&gdtr) : "memory");
}

void
x64_init_gdt_ap(void) {
    struct gdt64_descriptor gdtr;
    gdtr.address = (uint64_t)&x64_bsp_gdt64;
    gdtr.limit = sizeof(struct gdt64);
    asm volatile ("lgdtq (%0)" :: "r" (&gdtr) : "memory");
}

static void
x64_set_own_gdt_xcall(void *state)
{
    volatile int *done = state;

    printk("CPU (%ld) Resetting GDT\n", (sl_t)current_cpu_id());

    struct cpu *gen_cpu = cpu_from_id(current_cpu_id());
    struct x64_cpu *cpu = container_of(gen_cpu, struct x64_cpu, cpu);

    struct gdt64_descriptor gdtr;
    gdtr.address = (uint64_t)cpu->gdt;
    gdtr.limit = sizeof(struct gdt64);
    asm volatile ("lgdtq (%0)" :: "r" (&gdtr) : "memory");

    *done = 1;
}

#define X64_USERMODE_TRANSITION_STACK_SIZE 0x1000
static void __percpu *x64_usermode_transition_stack = PERCPU_NULL;

static void
x64_setup_tss_xcall(void *state)
{
    volatile atomic_t *counter = state;
    void *stack = percpu_ptr(x64_usermode_transition_stack);

    struct cpu *gen_cpu = cpu_from_id(current_cpu_id());
    struct x64_cpu *cpu = container_of(gen_cpu, struct x64_cpu, cpu);

    *(uint64_t*)(cpu->tss_segment + 0x4) = ((uintptr_t)stack + X64_USERMODE_TRANSITION_STACK_SIZE);

    printk("CPU (%ld) set user-mode to kernel mode stack %p\n", (sl_t)current_cpu_id(), stack);

    asm volatile ("movw %w0, %%ax; ltr %%ax;" :: "r" (X64_TSS_GDT_SEGMENT_OFFSET) : "rax", "memory");
    printk("CPU (%ld) loaded TSS segment\n", (sl_t)current_cpu_id());

    atomic_fetch_inc((atomic_t*)counter);
}

static int
x64_gdt_init_smp(void)
{
    pin_thread(current_thread());
    for(cpu_id_t id = 0; id < total_num_cpus(); id++) {
        struct cpu *gen_cpu = cpu_from_id(id);
        struct x64_cpu *cpu = container_of(gen_cpu, struct x64_cpu, cpu);

        if(gen_cpu->is_bsp) {
            cpu->gdt = &x64_bsp_gdt64;
            cpu->tss_segment = &x64_bsp_tss_data;
        } else {
            cpu->gdt = kmalloc(sizeof(struct gdt64));
            if(cpu->gdt == NULL) {
                return -ENOMEM;
            }
            memcpy(cpu->gdt, &x64_bsp_gdt64, sizeof(struct gdt64));

            cpu->tss_segment = kmalloc(X64_TSS_SEGMENT_SIZE);
            if(cpu->tss_segment == NULL) {
                return -ENOMEM;
            }
            memset(cpu->tss_segment, 0, X64_TSS_SEGMENT_SIZE);

            cpu->gdt->tss.base_low_24 = ((uintptr_t)cpu->tss_segment) & 0xFFFFFF;
            cpu->gdt->tss.base_high_40 = ((uintptr_t)cpu->tss_segment) >> 24;

            // Here we assume other CPU's can access our stack,
            // which might be an assumption we want to avoid long term
            volatile int done = 0;
            int res = xcall_run(id, x64_set_own_gdt_xcall, (void*)&done);
            if(res) {
                eprintk("Failed to xcall CPU (%ld) to reset local GDT! (err=%s)\n",
                        (sl_t)id, errnostr(res));
            }

            while(!done) {}
        }
    }

    unpin_thread(current_thread());

    // Set up the user -> kernel mode transition stack on each CPU
    x64_usermode_transition_stack = percpu_alloc(X64_USERMODE_TRANSITION_STACK_SIZE);
    if(x64_usermode_transition_stack == PERCPU_NULL) {
        return -ENOMEM;
    }

    volatile atomic_t counter = 0;
    xcall_broadcast(x64_setup_tss_xcall, (void*)&counter);
    while(counter < total_num_cpus()) {}

    return 0;
}
declare_init_desc(smp, x64_gdt_init_smp, "Setting Up percpu GDT TSS Segments");

