
#include <arch/arm64/cpu.h>

#include <devtree/devtree.h>
#include <devtree/driver.h>
#include <devtree/flat.h>
#include <devtree/match.h>
#include <devtree/node.h>

#include <kanawha/kmalloc.h>

DECLARE_PERCPU_VAR(mpid_t, arm64_mpid);

static int
arm64_dt_cpu_probe(struct dt_driver *driver, struct dt_node *node)
{
    return 0;
}

static int
arm64_dt_cpu_init(struct dt_driver *driver, struct dt_node *node)
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

    void __phys *reg_addr_mpid;
    size_t reg_size;
    res = dt_node_read_reg(node, 1, &reg_addr_mpid, &reg_size);
    if(res)
    {
        eprintk("Failed to read Device Tree \"cpu\" node MPID!\n");
        return res;
    }
    uint64_t mpid = (uint64_t)(uintptr_t)reg_addr_mpid;
    printk("Found MPID(0x%lx)\n", (ul_t)mpid);

    struct arm64_cpu *cpu = kzmalloc(sizeof(struct arm64_cpu), KM_KERNEL);
    if(cpu == NULL)
    {
        eprintk("Failed to allocate cpu struct for mpid=%lu\n", mpid);
        return res;
    }

    {
        char namebuf[32];
        snprintk(namebuf, 32, "cpu%lu", (ul_t)mpid);
        namebuf[32 - 1] = '\0';
        cpu->name = kstrdup(namebuf);
        if(cpu->name == NULL)
        {
            cpu->name = "";
        }
    }

    int is_bsp = (mpid == current_mpid());

    printk("found CPU \"%s\" is_bsp=%d\n", cpu->name, is_bsp);
    if(is_bsp)
    {
        cpu->cpu.flags |= CPU_FLAG_IS_BSP;
    }
    else
    {
        cpu->cpu.flags &= ~CPU_FLAG_IS_BSP;
    }
    res = register_cpu(&cpu->cpu, cpu->name);
    if(res)
    {
        eprintk("Failed to register CPU for MPID(%lu) (err=%s)\n",
                (ul_t)mpid,
                errnostr(res));
        kfree(cpu);
        return res;
    }

    node->driver_state = cpu;

    return 0;
}

static int
arm64_dt_cpu_deinit(struct dt_driver *driver, struct dt_node *node)
{
    printk("arm64_dt_cpu_deinit\n");
    return -EUNIMPL;
}


static struct dt_driver_ops arm64_dt_cpu_driver_ops = {
    .probe = arm64_dt_cpu_probe,
    .init_node = arm64_dt_cpu_init,
    .deinit_node = arm64_dt_cpu_deinit,
    .xlate_irq = dt_driver_cannot_xlate_irq,
};

static struct dt_node_id arm64_dt_cpu_driver_ids[] = {
    {.compatible = "", .type = "cpu",},
    {.compatible = "arm,arm710t", .type = "cpu",},
    {.compatible = "arm,arm720t", .type = "cpu",},
    {.compatible = "arm,arm740t", .type = "cpu",},
    {.compatible = "arm,arm7ej-s", .type = "cpu",},
    {.compatible = "arm,arm7tdmi", .type = "cpu",},
    {.compatible = "arm,arm7tdmi-s", .type = "cpu",},
    {.compatible = "arm,arm9es", .type = "cpu",},
    {.compatible = "arm,arm9ej-s", .type = "cpu",},
    {.compatible = "arm,arm920t", .type = "cpu",},
    {.compatible = "arm,arm922t", .type = "cpu",},
    {.compatible = "arm,arm925", .type = "cpu",},
    {.compatible = "arm,arm926e-s", .type = "cpu",},
    {.compatible = "arm,arm926ej-s", .type = "cpu",},
    {.compatible = "arm,arm940t", .type = "cpu",},
    {.compatible = "arm,arm946e-s", .type = "cpu",},
    {.compatible = "arm,arm966e-s", .type = "cpu",},
    {.compatible = "arm,arm968e-s", .type = "cpu",},
    {.compatible = "arm,arm9tdmi", .type = "cpu",},
    {.compatible = "arm,arm1020e", .type = "cpu",},
    {.compatible = "arm,arm1020t", .type = "cpu",},
    {.compatible = "arm,arm1022e", .type = "cpu",},
    {.compatible = "arm,arm1026ej-s", .type = "cpu",},
    {.compatible = "arm,arm1136j-s", .type = "cpu",},
    {.compatible = "arm,arm1136jf-s", .type = "cpu",},
    {.compatible = "arm,arm1156t2-s", .type = "cpu",},
    {.compatible = "arm,arm1156t2f-s", .type = "cpu",},
    {.compatible = "arm,arm1176jzf", .type = "cpu",},
    {.compatible = "arm,arm1176jz-s", .type = "cpu",},
    {.compatible = "arm,arm1176jzf-s", .type = "cpu",},
    {.compatible = "arm,arm11mpcore", .type = "cpu",},
    {.compatible = "arm,cortex-a5", .type = "cpu",},
    {.compatible = "arm,cortex-a7", .type = "cpu",},
    {.compatible = "arm,cortex-a8", .type = "cpu",},
    {.compatible = "arm,cortex-a9", .type = "cpu",},
    {.compatible = "arm,cortex-a12", .type = "cpu",},
    {.compatible = "arm,cortex-a15", .type = "cpu",},
    {.compatible = "arm,cortex-a17", .type = "cpu",},
    {.compatible = "arm,cortex-a53", .type = "cpu",},
    {.compatible = "arm,cortex-a57", .type = "cpu",},
    {.compatible = "arm,cortex-a72", .type = "cpu",},
    {.compatible = "arm,cortex-a73", .type = "cpu",},
    {.compatible = "arm,cortex-m0", .type = "cpu",},
    {.compatible = "arm,cortex-m0+", .type = "cpu",},
    {.compatible = "arm,cortex-m1", .type = "cpu",},
    {.compatible = "arm,cortex-m3", .type = "cpu",},
    {.compatible = "arm,cortex-m4", .type = "cpu",},
    {.compatible = "arm,cortex-r4", .type = "cpu",},
    {.compatible = "arm,cortex-r5", .type = "cpu",},
    {.compatible = "arm,cortex-r7", .type = "cpu",},
    {.compatible = "brcm,brahma-b15", .type = "cpu",},
    {.compatible = "brcm,brahma-b53", .type = "cpu",},
    {.compatible = "brcm,vulcan", .type = "cpu",},
    {.compatible = "cavium,thunder", .type = "cpu",},
    {.compatible = "cavium,thunder2", .type = "cpu",},
    {.compatible = "faraday,fa526", .type = "cpu",},
    {.compatible = "intel,sa110", .type = "cpu",},
    {.compatible = "intel,sa1100", .type = "cpu",},
    {.compatible = "marvell,feroceon", .type = "cpu",},
    {.compatible = "marvell,mohawk", .type = "cpu",},
    {.compatible = "marvell,pj4a", .type = "cpu",},
    {.compatible = "marvell,pj4b", .type = "cpu",},
    {.compatible = "marvell,sheeva-v5", .type = "cpu",},
    {.compatible = "nvidia,tegra132-denver", .type = "cpu",},
    {.compatible = "nvidia,tegra186-denver", .type = "cpu",},
    {.compatible = "nvidia,tegra194-carmel", .type = "cpu",},
    {.compatible = "qcom,krait", .type = "cpu",},
    {.compatible = "qcom,kryo", .type = "cpu",},
    {.compatible = "qcom,kryo385", .type = "cpu",},
    {.compatible = "qcom,scorpion", .type = "cpu",},
};

static struct dt_driver arm64_dt_cpu_driver = {
    .ids = arm64_dt_cpu_driver_ids,
    .num_ids = sizeof(arm64_dt_cpu_driver_ids)/sizeof(arm64_dt_cpu_driver_ids[0]),
    .ops = &arm64_dt_cpu_driver_ops,
};

static int
register_arm64_dt_cpu_driver(void)
{
    int res;

    res = register_dt_driver(&arm64_dt_cpu_driver);
    if(res)
    {
        return res;
    }

    return 0;
}
declare_init_desc(topo,
                  register_arm64_dt_cpu_driver,
                  "Registering Device Tree ARM64 CPU Node Driver");
