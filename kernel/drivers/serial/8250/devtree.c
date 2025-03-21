
#include <kanawha/init.h>
#include <devtree/devtree.h>
#include <devtree/driver.h>
#include <devtree/match.h>
#include <devtree/flat.h>

#include <kanawha/mmio.h>
#include <kanawha/kmalloc.h>

#include <drivers/serial/8250/mmio.h>

struct dt_uart_8250
{
    struct mmio_uart_8250 uart;
    void __mmio *mmio_base;
    size_t mmio_size;

    struct dt_node *node;
};

static int
dt_8250_probe(
        struct dt_driver *driver,
        struct dt_node *node)
{
    return 0;
}

static int
dt_8250_init_node(
        struct dt_driver *driver,
        struct dt_node *node)
{
    int res;

    struct dt_uart_8250 *uart = kmalloc(sizeof(struct dt_uart_8250));
    if(uart == NULL) {
        eprintk("Failed allocate device tree 8250 struct!\n");
        return -ENOMEM;
    }
    memset(uart, 0, sizeof(struct dt_uart_8250));

    uart->node = node;

    void __phys *phys_base;
    size_t phys_size;

    res = dt_node_read_reg(
            node,
            1,
            &phys_base,
            &phys_size);
    if(res) {
        eprintk("Failed to read device tree 8250 \"reg\" property! (err=%s)\n",
                errnostr(res));
        kfree(uart);
        return res;
    }

    uart->mmio_base = mmio_map(phys_base, phys_size);
    if(uart->mmio_base == NULL) {
        eprintk("Failed to map device tree 8250 mmio region!\n");
        kfree(uart);
        return -ENOMEM;
    }
    uart->mmio_size = phys_size;

    uintptr_t shift;
    res = dt_node_read_property_unsigned(
            node,
            "reg-shift",
            &shift);
    if(res) {
        shift = 0;
    }

    const char *name = dt_node_get_name(node);

    printk("Registering Device Tree 8250 Device \"%s\"\n", name);
    res = register_mmio_uart_8250(
            name,
            &uart->uart,
            uart->mmio_base,
            uart->mmio_size,
            shift);
    if(res) {
        mmio_unmap(uart->mmio_base, uart->mmio_size);
        kfree(uart);
        return res;
    }

    return 0;
}

static int
dt_8250_deinit_node(
        struct dt_driver *driver,
        struct dt_node *node)
{
    int res;
    return -EUNIMPL;
}

struct dt_driver_ops
dt_8250_driver_ops = {
    .probe = dt_8250_probe,
    .init_node = dt_8250_init_node,
    .deinit_node = dt_8250_deinit_node,
    .xlate_irq = dt_driver_cannot_xlate_irq,
};

struct dt_node_id
dt_8250_ids[] = {
    { .compatible = "serial" },
    { .compatible = "ns8250" },
    { .compatible = "ns16450" },
    { .compatible = "ns16550a" },
    { .compatible = "ns16550" },
    { .compatible = "ns16750" },
    { .compatible = "ns16850" },
};

struct dt_driver
dt_8250_driver = {
    .num_ids = sizeof(dt_8250_ids)/sizeof(struct dt_node_id),
    .ids = dt_8250_ids,
    .ops = &dt_8250_driver_ops,
};

static int
register_dt_8250_driver(void) {
    int res;
    res = register_dt_driver(&dt_8250_driver);
    if(res) {
        return res;
    }
    return 0;
}
declare_init_desc(device, register_dt_8250_driver, "Registering Device Tree 8250 Driver");

