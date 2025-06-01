
#include <arch/x64/cpu.h>
#include <arch/x64/lapic.h>
#include <arch/x64/apic_timer.h>
#include <kanawha/stddef.h>
#include <kanawha/lock.h>
#include <kanawha/ptree.h>

static DECLARE_PTREE(apic_tree);
DEFINE_LOCAL_THREAD_LOCK(apic_tree_lock);

int
x64_bsp_register_smp_cpu(
        struct x64_cpu *cpu,
        apic_id_t apic_id,
        int is_bsp)
{
    int res;

    apic_tree_lock_acquire();

    struct ptree_node *node;
    node = ptree_get(&apic_tree, (uintptr_t)apic_id);
    if(node) {
        apic_tree_lock_release();
        eprintk("Tried to register CPU with APICID=0x%lx multiple times!\n",
                (unsigned long)apic_id);
        return -EEXIST;
    }

    cpu->apic.id = apic_id;
    cpu->apic_tree_node.key = (uintptr_t)apic_id;

    if(is_bsp) {
        printk("BSP (%d) APICID = 0x%08x\n", cpu->cpu.id, cpu->apic.id);
    } else {
        printk("AP (%d) APICID = 0x%08x\n", cpu->cpu.id, cpu->apic.id);
    }

    res = bsp_register_smp_cpu(&cpu->cpu, is_bsp);
    if(res) {
        apic_tree_lock_release();
        return res;
    }

    res = bsp_register_cpu_lapic(cpu);
    if(res) {
        apic_tree_lock_release();
        return res;
    }

    res = register_cpu_lapic_timer(cpu);

    ptree_insert(&apic_tree, &cpu->apic_tree_node, (uintptr_t)apic_id);

    apic_tree_lock_release();

    printk("Registered CPU %ld with APIC ID 0x%lx\n",
            (long)cpu->cpu.id, (unsigned long)cpu->apic.id);

    if(is_bsp) {
        printk("Initializing BSP LAPIC\n");
        res = lapic_init_current();
        if(res) {
            return res;
        }
        res = apic_timer_init_current();
        if(res) {
            return res;
        }
    }

    return 0;
}

struct x64_cpu *
cpu_from_apic_id(apic_id_t id)
{
    struct ptree_node *node;

    apic_tree_lock_acquire();
    node = ptree_get(&apic_tree, (uintptr_t)id);
    apic_tree_lock_release();

    if(node == NULL) {
        return NULL;
    }

    return container_of(node, struct x64_cpu, apic_tree_node);
}

apic_id_t
apic_id_from_cpu(struct cpu *gen_cpu) {
    struct x64_cpu *cpu =
        container_of(gen_cpu, struct x64_cpu, cpu);
    return cpu->apic.id;
}

