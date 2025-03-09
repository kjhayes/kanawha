
#include <devtree/driver.h>
#include <devtree/match.h>

static int
riscv64_dt_cpus_probe(
        struct dt_driver *driver,
        struct dt_node *node)
{
    printk("riscv64_dt_cpus_probe\n");
    return -EUNIMPL;
}

static int
riscv64_dt_cpus_init(
        struct dt_driver *driver,
        struct dt_node *node)
{
    printk("riscv64_dt_cpus_init\n");
    return -EUNIMPL;
}

static int
riscv64_dt_cpus_deinit(
        struct dt_driver *driver,
        struct dt_node *node)
{
    printk("riscv64_dt_cpus_deinit\n");
    return -EUNIMPL;
}

static struct dt_driver_ops
riscv64_dt_cpus_driver_ops = {
    .probe = riscv64_dt_cpus_probe,
    .init_node = riscv64_dt_cpus_init,
    .deinit_node = riscv64_dt_cpus_deinit,
    .xlate_irq = dt_driver_cannot_xlate_irq,
};

static struct dt_node_id
riscv64_dt_cpus_driver_ids[] = {
    {
        .name = "cpus"
    }
};

static struct dt_driver
riscv64_dt_cpus_driver = {
    .ids = riscv64_dt_cpus_driver_ids,
    .num_ids = 1,
    .ops = &riscv64_dt_cpus_driver_ops,
};

static int
register_riscv64_dt_cpus_driver(void) {
    return register_dt_driver(&riscv64_dt_cpus_driver);
}
declare_init_desc(topo, register_riscv64_dt_cpus_driver, "Registering Device Tree RISC-V /cpus Node Driver");

