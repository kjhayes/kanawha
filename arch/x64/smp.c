
#include <arch/x64/cpu.h>
#include <arch/x64/lapic.h>
#include <kanawha/cpu.h>
#include <kanawha/percpu.h>
#include <kanawha/clk.h>
#include <kanawha/init.h>
#include <kanawha/page_alloc.h>
#include <kanawha/vmem.h>
#include <kanawha/string.h>

static volatile cpu_id_t booting_ap = NULL_CPU_ID;

int
x64_ap_notify_booted(void) {
    if(booting_ap != current_cpu_id()) {
        return -EINVAL;
    }

    booting_ap = NULL_CPU_ID;
    asm volatile ("mfence" ::: "memory");
    return 0;
}

cpu_id_t
x64_get_booting_ap(void) {
    return booting_ap;
}

#define AP_TRAMPOLINE_PAGE_ORDER 12
#define AP_BOOT_STACK_ORDER 21

extern char x64_ap_trampoline_start[];
extern char x64_ap_trampoline_end[];
extern char x64_ap_trampoline_ap_launched_byte[];
extern char x64_ap_trampoline_self_ptr[];
extern char x64_ap_trampoline_virtual_stack_base[];

static int
x64_bsp_bringup_aps(void)
{
    int res;

    struct cpu *gen_cpu = cpu_from_id(current_cpu_id());
    if(gen_cpu == NULL) {
        return -ENXIO;
    }
    struct x64_cpu *bsp =
        container_of(gen_cpu, struct x64_cpu, cpu);

    size_t num_brought_up = 0;

    paddr_t trampoline_paddr;

    res = page_alloc(AP_TRAMPOLINE_PAGE_ORDER, &trampoline_paddr, PAGE_ALLOC_16BIT);
    if(res) {
        eprintk("Failed to allocate 16-bit trampoline page for AP bringup! (err=%s)\n",
                errnostr(res));
        return res;
    }

    paddr_t stack_paddr;
    res = page_alloc(AP_BOOT_STACK_ORDER, &stack_paddr, 0x0); // the AP won't use this before long mode,
                                                              // so we don't need 16-bit addresses
    if(res) {
        page_free(AP_TRAMPOLINE_PAGE_ORDER, trampoline_paddr);
        return res;
    }
    void *virtual_stack = (void*)__va(stack_paddr);

    void *trampoline = (void*)__va(trampoline_paddr);
    memset(trampoline, 0, (1ULL<<AP_TRAMPOLINE_PAGE_ORDER));

    size_t trampoline_size =
        (uintptr_t)x64_ap_trampoline_end - (uintptr_t)x64_ap_trampoline_start;

    memcpy(trampoline, x64_ap_trampoline_start, trampoline_size);

    dprintk("ap_trampoline_start = %p\n",    x64_ap_trampoline_start);
    dprintk("ap_trampoline_end = %p\n",      x64_ap_trampoline_end);
    dprintk("ap_trampoline_launched = %p\n", x64_ap_trampoline_ap_launched_byte);

    dprintk("AP Trampoline Size: 0x%llx bytes\n"
            "AP Trampoline Addr: %p\n",
            (ull_t)trampoline_size,
            trampoline_paddr);

    size_t trampoline_pfn = trampoline_paddr >> 12;

    volatile uint8_t *ap_launched_byte =
        trampoline + ((uintptr_t)x64_ap_trampoline_ap_launched_byte - (uintptr_t)x64_ap_trampoline_start);

    volatile uint16_t *trampoline_self_ptr =
        trampoline + ((uintptr_t)x64_ap_trampoline_self_ptr- (uintptr_t)x64_ap_trampoline_start);
    *trampoline_self_ptr = (uint16_t)trampoline_paddr;

    volatile void **trampoline_virtual_stack_base =
        trampoline + ((uintptr_t)x64_ap_trampoline_virtual_stack_base- (uintptr_t)x64_ap_trampoline_start);
    *trampoline_virtual_stack_base = virtual_stack;

    for(cpu_id_t ap_id = 0; ap_id < total_num_cpus(); ap_id++)
    {
        if(ap_id == bsp->cpu.id) {
            continue;
        }

        struct cpu *gen_ap = cpu_from_id(ap_id);
        if(gen_ap == NULL) {
            wprintk("total_num_cpus() = %ld, but AP %ld cannot be found!\n",
                    (sl_t)total_num_cpus(), (sl_t)ap_id);
        }
        struct x64_cpu *ap =
            container_of(gen_ap, struct x64_cpu, cpu);

        // Make sure the previous AP finished booting
        while(booting_ap != NULL_CPU_ID) {}

        // Set up the next AP to boot
        booting_ap = ap_id;
        *ap_launched_byte = 0;
        asm volatile ("mfence" ::: "memory");

        printk("Launching AP %ld\n", (sl_t)gen_ap->id);

        res = lapic_send_ipi(
                &bsp->apic,
                ap->apic.id,
                0x0, // vector
                LAPIC_MT_INIT,
                0, // physical addressing
                1, // assert
                LAPIC_TRIGGER_MODE_EDGE);
        if(res) {
            eprintk("Failed to send INIT IPI to APIC ID 0x%lx (err=%s)\n",
                    (ul_t)ap->apic.id, errnostr(res));
            continue;
        }

        printk("Sent INIT IPI to APIC %ld\n", (sl_t)ap->apic.id);

        // Intel says to wait for 10ms after an INIT IPI
        res = clk_delay(msec_to_duration(10));
        if(res) {
            eprintk("Failed to delay after INIT IPI! (err=%s)\n",
                    errnostr(res));
            continue;
        }

        res = lapic_send_ipi(
                &bsp->apic,
                ap->apic.id,
                trampoline_pfn, // vector
                LAPIC_MT_STARTUP,
                0, // physical addressing
                1, // assert
                LAPIC_TRIGGER_MODE_EDGE);

        if(res) {
            panic("Failed to Send SIPI (err=%s)\n",
                    errnostr(res));
        } else {
            printk("Sent SIPI\n");
        }


        res = clk_delay(msec_to_duration(1));
        if(res) {
            panic("Failed to delay after SIPI (err=%s)\n",
                    errnostr(res));
        }

        if(*ap_launched_byte == 0) {
            res = lapic_send_ipi(
                &bsp->apic,
                ap->apic.id,
                trampoline_pfn, // vector
                LAPIC_MT_STARTUP,
                0, // physical addressing
                1, // assert
                LAPIC_TRIGGER_MODE_EDGE);
            if(res) {
                panic("Failed to Send Second SIPI (err=%s)\n",
                        errnostr(res));
            } else {
                printk("Sent Second SIPI\n");
            }

            res = clk_delay(sec_to_duration(1));
            if(res) {
                panic("Failed to delay after second SIPI (err=%s)\n",
                        errnostr(res));
            }
        }

        while(*ap_launched_byte != 1) {
            panic("Failed to Launch AP %ld\n",
                    ap->cpu.id);
        }

        printk("AP %ld Is Running\n", ap->cpu.id);
    }

    printk("BSP Waiting for all AP(s) to finish booting...\n");
    while(booting_ap != NULL_CPU_ID) {}

    printk("All AP(s) Finished Booting!\n");

    // Free the trampoline page
    page_free(AP_TRAMPOLINE_PAGE_ORDER, trampoline_paddr);
    page_free(AP_BOOT_STACK_ORDER, stack_paddr);

    return 0;
}

declare_init_desc(smp_bringup, x64_bsp_bringup_aps, "Booting AP(s) From BSP");
