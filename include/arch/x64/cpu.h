#ifndef __KANAWHA__X64_CPU_H__
#define __KANAWHA__X64_CPU_H__

#include <kanawha/cpu.h>
#include <kanawha/ptree.h>
#include <arch/x64/lapic.h>
#include <arch/x64/apic_timer.h>
#include <arch/x64/gdt.h>

struct x64_cpu
{
    struct cpu cpu;

    struct lapic apic;
    struct lapic_timer apic_timer;

    struct gdt64 *gdt;
    void *tss_segment;

    struct ptree_node apic_tree_node;
};

int
x64_bsp_register_smp_cpu(
        struct x64_cpu *cpu,
        apic_id_t apic_id,
        int is_bsp);

struct x64_cpu *
cpu_from_apic_id(apic_id_t id);

apic_id_t
apic_id_from_cpu(struct cpu *cpu);

#endif
