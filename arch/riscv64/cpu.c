
#include <devtree/devtree.h>
#include <devtree/driver.h>
#include <devtree/flat.h>
#include <devtree/match.h>
#include <devtree/node.h>

#include <arch/riscv64/cpu.h>
#include <arch/riscv64/hlic.h>
#include <arch/riscv64/trap.h>

#include <kanawha/irq.h>
#include <kanawha/irq_domain.h>
#include <kanawha/kmalloc.h>
#include <kanawha/list.h>
#include <kanawha/string.h>

DECLARE_PERCPU_VAR(hartid_t, riscv64_hartid);
DECLARE_PERCPU_VAR(freq_t, riscv64_timebase_freq);

static int
dt_cpu_node_find_timebase(struct dt_node *node, freq_t *freq_out)
{
    struct fdt *fdt = devtree_get_fdt(node->dt);
    struct fdt_node *fdt_node = dt_node_get_fdt_node(node);

    struct fdt_property *timebase_prop =
        fdt_find_property_by_name(fdt, fdt_node, "timebase-frequency");
    if(timebase_prop == NULL)
    {
        if(node->parent == NULL)
        {
            return -EINVAL;
        }
        struct fdt_node *parent_fdt_node = dt_node_get_fdt_node(node->parent);
        timebase_prop = fdt_find_property_by_name(fdt,
                                                  parent_fdt_node,
                                                  "timebase-frequency");
        if(timebase_prop == NULL)
        {
            return -EINVAL;
        }
    }

    size_t len = fdt_property_size(fdt, timebase_prop);
    fdt32_t *cells = fdt_property_data(fdt, timebase_prop);

    hz_t hz;
    switch(len)
    {
    case 4:
        hz = fdttoh32(*cells);
        break;
    case 8:
        hz = fdttoh32(*(fdt64_t *)cells);
        break;
    default:
        return -EINVAL;
    }

    freq_t freq = hz_to_freq(hz);

    if(freq_out)
    {
        *freq_out = freq;
    }

    return 0;
}

static int
riscv64_dt_cpu_probe(struct dt_driver *driver, struct dt_node *node)
{
    return 0;
}

static int
riscv64_dt_cpu_init(struct dt_driver *driver, struct dt_node *node)
{
    // We must be running on the BSP

    int res;

    res = dt_node_check_device_type(node, "cpu");
    if(res)
    {
        // This is not a CPU node
        return res;
    }

    size_t reg_count = dt_node_reg_count(node);
    if(reg_count != 1)
    {
        eprintk("Failed to get Device Tree \"cpu\" node reg property "
                "count!\n");
        return -EINVAL;
    }

    void __phys *reg_addr_hartid;
    size_t reg_size;
    res = dt_node_read_reg(node, 1, &reg_addr_hartid, &reg_size);
    if(res)
    {
        eprintk("Failed to read Device Tree \"cpu\" node HartID!\n");
        return res;
    }
    hartid_t hartid = (hartid_t)(uintptr_t)reg_addr_hartid;
    dprintk("Found HARTID(0x%lx)\n", (ul_t)hartid);

    struct riscv64_cpu *cpu = kmalloc(sizeof(struct riscv64_cpu), KM_KERNEL);
    if(cpu == NULL)
    {
        eprintk("Failed to allocate cpu struct for hartid=%lu\n", hartid);
        return res;
    }
    memset(cpu, 0, sizeof(struct riscv64_cpu));

    {
        char namebuf[32];
        snprintk(namebuf, 32, "hart%ld", current_hartid());
        namebuf[32-1] = '\0';
        cpu->name = kstrdup(namebuf);
        if(cpu->name == NULL) {
            cpu->name = "";
        }
    }

    int is_bsp = (hartid == current_hartid());

    dprintk("hartid=0x%lx, is_bsp = %d\n", (ul_t)hartid, is_bsp);
    if(is_bsp) {
        cpu->cpu.flags |= CPU_FLAG_IS_BSP;
    } else {
        cpu->cpu.flags &= ~CPU_FLAG_IS_BSP;
    }
    res = register_cpu(&cpu->cpu, cpu->name);
    if(res)
    {
        eprintk("Failed to register CPU for HartID(%lu)\n", hartid);
        kfree(cpu);
        return res;
    }

    node->driver_state = cpu;

    provide_hartid(hartid, cpu->cpu.id);

    struct dt_node *intc_node = NULL;
    ilist_node_t *list_node;
    ilist_for_each(list_node, &node->children)
    {
        struct dt_node *child =
            container_of(list_node, struct dt_node, child_node);
        static struct dt_node_id id = {
            .name = NULL,
            .type = NULL,
            .compatible = "riscv,cpu-intc",
        };
        if(dt_node_check_id(child, &id) == 0)
        {
            intc_node = child;
            break;
        }
    }

    if(intc_node != NULL)
    {
        res = riscv64_setup_cpu_hlic(cpu, intc_node);
        if(res)
        {
            panic("Failed to setup RISCV CPU HLIC!\n");
        }
    }
    else
    {
        wprintk("RISC-V CPU node has no HLIC node!\n");
    }

    freq_t timebase;
    res = dt_cpu_node_find_timebase(node, &timebase);
    if(res)
    {
        panic("Failed to find CPU node timebase!\n");
    }

    freq_t *percpu_timebase =
        percpu_ptr_specific(percpu_addr(riscv64_timebase_freq), cpu->cpu.id);
    *percpu_timebase = timebase;

    printk("CPU(%lu) timebase frequency = %lu HZ\n",
           (ul_t)cpu->cpu.id,
           (ul_t)freq_to_hz(timebase));

    return 0;
}

static int
riscv64_dt_cpu_deinit(struct dt_driver *driver, struct dt_node *node)
{
    printk("riscv64_dt_cpu_deinit\n");
    return -EUNIMPL;
}

static struct dt_driver_ops riscv64_dt_cpu_driver_ops = {
    .probe = riscv64_dt_cpu_probe,
    .init_node = riscv64_dt_cpu_init,
    .deinit_node = riscv64_dt_cpu_deinit,
    .xlate_irq = dt_driver_cannot_xlate_irq,
};

static struct dt_node_id riscv64_dt_cpu_driver_ids[] = {{
    .compatible = "riscv",
    .type = "cpu",
}};

static struct dt_driver riscv64_dt_cpu_driver = {
    .ids = riscv64_dt_cpu_driver_ids,
    .num_ids = 1,
    .ops = &riscv64_dt_cpu_driver_ops,
};

static int
register_riscv64_dt_cpu_driver(void)
{
    int res;

    res = register_dt_driver(&riscv64_dt_cpu_driver);
    if(res)
    {
        return res;
    }

    return 0;
}
declare_init_desc(topo,
                  register_riscv64_dt_cpu_driver,
                  "Registering Device Tree RISC-V CPU Node Driver");
