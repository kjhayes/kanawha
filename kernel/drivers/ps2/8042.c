
#include <kanawha/spinlock.h>
#include <kanawha/pio.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/init.h>
#include <kanawha/irq.h>
#include <kanawha/irq_domain.h>
#include <kanawha/assert.h>
#include <kanawha/vmem.h>
#include <arch/x64/pic.h>
#include <drivers/ps2/port.h>

#define PS2_8042_STANDARD_DATA_PORT    0x60
#define PS2_8042_STANDARD_COMMAND_PORT 0x64
#define PS2_8042_STANDARD_STATUS_PORT  0x64

struct ps2_8042;
struct ps2_8042_port;

struct ps2_8042
{
    spinlock_t lock;

    pio_t data_port;
    pio_t command_port;
    pio_t status_port;

    struct ps2_8042_port *first_port;
    struct ps2_8042_port *second_port;
};

#define PS2_PORT_BUFSIZE 64

struct ps2_8042_port
{
    struct ps2_port port;
    struct ps2_8042 *controller;
    struct irq_action *action;
};

static int
ps2_8042_wait_input_buf(
        struct ps2_8042 *ps2)
{
    // TODO: Add a timeout
    do {
        uint8_t status = inb(ps2->status_port);
        if((status & 0b10) == 0) {
            break;
        }
    } while(1);
    return 0;
}

static int
ps2_8042_wait_output_buf(
        struct ps2_8042 *ps2)
{
    // TODO: Add a timeout
    do {
        uint8_t status = inb(ps2->status_port);
        if((status & 0b01) != 0) {
            break;
        }
    } while(1);
    return 0;
}

static int
ps2_8042_cmd(
        struct ps2_8042 *ps2,
        uint8_t cmd)
{
    int res;
    spin_lock(&ps2->lock);
    res = ps2_8042_wait_input_buf(ps2);
    if(res) {
        spin_unlock(&ps2->lock);
        return res;
    }
    outb(ps2->command_port, cmd);
    spin_unlock(&ps2->lock);
    return 0;
}

static int
ps2_8042_data(
        struct ps2_8042 *ps2,
        uint8_t data)
{
    int res;
    spin_lock(&ps2->lock);
    res = ps2_8042_wait_input_buf(ps2);
    if(res) {
        spin_unlock(&ps2->lock);
        return res;
    }
    outb(ps2->data_port, data);
    spin_unlock(&ps2->lock);
    return 0;
}

static int
ps2_8042_cmd_data(
        struct ps2_8042 *ps2,
        uint8_t cmd,
        uint8_t data)
{
    int res;
    spin_lock(&ps2->lock);
    res = ps2_8042_wait_input_buf(ps2);
    if(res) {
        spin_unlock(&ps2->lock);
        return res;
    } 
    outb(ps2->command_port, cmd);
    res = ps2_8042_wait_input_buf(ps2);
    if(res) {
        spin_unlock(&ps2->lock);
        return res;
    }
    outb(ps2->data_port, data);
    spin_unlock(&ps2->lock);
    return 0;
}

static int
ps2_8042_cmd_resp(
        struct ps2_8042 *ps2,
        uint8_t cmd,
        uint8_t *resp)
{
    int res;
    spin_lock(&ps2->lock);
    res = ps2_8042_wait_input_buf(ps2);
    if(res) {
        spin_unlock(&ps2->lock);
        return res;
    }
    outb(ps2->command_port, cmd);
    res = ps2_8042_wait_output_buf(ps2);
    if(res) {
        spin_unlock(&ps2->lock);
        return res;
    }
    *resp = inb(ps2->data_port);
    spin_unlock(&ps2->lock);
    return 0;
}

static int
ps2_8042_cmd_data_resp(
        struct ps2_8042 *ps2,
        uint8_t cmd,
        uint8_t data,
        uint8_t *resp)
{
    int res;
    spin_lock(&ps2->lock);
    res = ps2_8042_wait_input_buf(ps2);
    if(res) {
        spin_unlock(&ps2->lock);
        return res;
    }
    outb(ps2->command_port, cmd);
    res = ps2_8042_wait_input_buf(ps2);
    if(res) {
        spin_unlock(&ps2->lock);
        return res;
    }
    outb(ps2->data_port, data);
    res = ps2_8042_wait_output_buf(ps2);
    if(res) {
        spin_unlock(&ps2->lock);
        return res;
    }
    *resp = inb(ps2->data_port);
    spin_unlock(&ps2->lock);
    return 0;
}

static int
ps2_8042_read_cfg(
        struct ps2_8042 *ps2,
        uint8_t *cfg)
{
    return ps2_8042_cmd_resp(ps2, 0x20, cfg);
}

static int
ps2_8042_write_cfg(
        struct ps2_8042 *ps2,
        uint8_t cfg)
{
    return ps2_8042_cmd_data(ps2, 0x60, cfg);
}

// Returns 0 on success
static int
ps2_8042_self_test(
        struct ps2_8042 *ps2)
{
    int res;
    uint8_t resp;
    res = ps2_8042_cmd_resp(ps2, 0xAA, &resp);
    if(res) {
        return res;
    }
    if(resp == 0x55) {
        return 0;
    } else if(resp == 0xFC) {
        // "proper" failure
        return -EFAULT;
    } else {
        return -EINVAL;
    }
}

static int
ps2_8042_flush_output_buf(
        struct ps2_8042 *ps2)
{
    int res;
    spin_lock(&ps2->lock);
    uint8_t status;
    status = inb(ps2->status_port);
    if(status & 0b01) {
        uint8_t val = inb(ps2->data_port);
    }
    spin_unlock(&ps2->lock);
    return 0;
}

static int
ps2_8042_port_irq_handler(
        struct excp_state *excp_state,
        struct irq_action *action)
{
    dprintk("8042 IRQ\n");
    struct ps2_8042_port *port = action->handler_data.priv_data;
    DEBUG_ASSERT(KERNEL_ADDR(port));
    DEBUG_ASSERT(KERNEL_ADDR(port->controller));
    uint8_t data = inb(port->controller->data_port); 
    if(port->port.callback != NULL) {
        DEBUG_ASSERT(KERNEL_ADDR(port->port.callback));
        (*port->port.callback)(&port->port, port->port.callback_data, data);
    }
    dprintk("8042 IRQ END\n");
    return IRQ_HANDLED;
}

static int
ps2_8042_first_port_send(
        struct ps2_port *port,
        uint8_t data)
{
    DEBUG_ASSERT(KERNEL_ADDR(port));
    struct ps2_8042_port *ps2_port =
        container_of(port, struct ps2_8042_port, port);
    return ps2_8042_data(ps2_port->controller, data);
}

static int
ps2_8042_second_port_send(
        struct ps2_port *port,
        uint8_t data)
{
    DEBUG_ASSERT(KERNEL_ADDR(port));
    struct ps2_8042_port *ps2_port =
        container_of(port, struct ps2_8042_port, port);
    return ps2_8042_cmd_data(ps2_port->controller, 0xD4, data);
}

static struct ps2_port_ops
ps2_8042_first_port_ops = {
    .send = ps2_8042_first_port_send,
};

static struct ps2_port_ops
ps2_8042_second_port_ops = {
    .send = ps2_8042_second_port_send,
};

static int
ps2_8042_probe(void)
{
    int res;

    struct ps2_8042 *ps2 = kmalloc(sizeof(struct ps2_8042));
    if(ps2 == NULL) {
        res = -ENOMEM;
        goto err0;
    }
    memset(ps2, 0, sizeof(struct ps2_8042));

    spinlock_init(&ps2->lock);
    ps2->data_port    = PS2_8042_STANDARD_DATA_PORT;
    ps2->command_port = PS2_8042_STANDARD_COMMAND_PORT;
    ps2->status_port  = PS2_8042_STANDARD_STATUS_PORT;

    // Disable Both (ignored if only one) Ports
    res = ps2_8042_cmd(ps2, 0xAD);
    if(res) {
        goto err1;
    }
    res = ps2_8042_cmd(ps2, 0xA7);
    if(res) {
        goto err1;
    }

    res = ps2_8042_flush_output_buf(ps2);
    if(res) {
        goto err1;
    }

    uint8_t cfg;
    res = ps2_8042_read_cfg(ps2, &cfg);
    if(res) {
        goto err1;
    }

    cfg &= ~(1ULL<<0); // Disable First Port IRQ
    cfg &= ~(1ULL<<4); // Enable First Port Clock
    cfg &= ~(1ULL<<6); // Disable First Port Translation

    res = ps2_8042_write_cfg(ps2, cfg);
    if(res) {
        goto err1;
    }

    res = ps2_8042_self_test(ps2);
    if(res) {
        wprintk("PS2 8042: Failed Self Test! (err=%s)\n",
                errnostr(res));
        goto err1;
    }

    // Write the config byte again incase the
    // hardware reset during the self test.
    res = ps2_8042_write_cfg(ps2, cfg);
    if(res) {
        goto err1;
    }

    // Allocate the first port struct / buffer
    ps2->first_port = kmalloc(sizeof(struct ps2_8042_port));
    if(ps2->first_port == NULL) {
        res = -ENOMEM;
        goto err1;
    }
    memset(ps2->first_port, 0, sizeof(struct ps2_8042_port));
    ps2->first_port->controller = ps2;
    ps2->first_port->port.ops = &ps2_8042_first_port_ops;
    ps2->first_port->port.callback = NULL;
    ps2->first_port->port.callback_data = NULL;

    // Try to detect the secnd port
    res = ps2_8042_cmd(ps2, 0xA8);
    if(res) {
        goto err2;
    }

    res = ps2_8042_read_cfg(ps2, &cfg);
    if(res) {
        goto err2;
    }

    if(cfg & (1<<5)) {
        // Second port is not present
        ps2->second_port = NULL;
    } else {
        // The second port exists, disable it again
        res = ps2_8042_cmd(ps2, 0xA7);
        if(res) {
            ps2->second_port = NULL;
            goto err2;
        }

        uint8_t cfg;
        res = ps2_8042_read_cfg(ps2, &cfg);
        if(res) {
            ps2->second_port = NULL;
            goto err2;
        }
    
        cfg &= ~(1ULL<<1); // Disable Second Port IRQ
        cfg &= ~(1ULL<<5); // Enable Second Port Clock
    
        res = ps2_8042_write_cfg(ps2, cfg);
        if(res) {
            ps2->second_port = NULL;
            goto err2;
        }

        // Allocate the second port struct / buffer
        ps2->second_port = kmalloc(sizeof(struct ps2_8042_port));
        if(ps2->second_port == NULL) {
            res = -ENOMEM;
            ps2->second_port = NULL;
            goto err2;
        }
        memset(ps2->second_port, 0, sizeof(struct ps2_8042_port));
        ps2->second_port->controller = ps2;
        ps2->second_port->port.ops = &ps2_8042_second_port_ops;
        ps2->second_port->port.callback = NULL;
        ps2->second_port->port.callback_data = NULL;
    }

    // Test Both Ports Again
    uint8_t port_test_result;

    // Testing first port
    res = ps2_8042_cmd_resp(ps2, 0xAB, &port_test_result);
    if(res || port_test_result != 0) {
        wprintk("8042 PS/2: First Port Failed Test\n");
        kfree(ps2->first_port);
        ps2->first_port = NULL;
    }

    res = ps2_8042_cmd_resp(ps2, 0xA9, &port_test_result);
    if(res || port_test_result != 0) {
        wprintk("8042 PS/2: Second Port Failed Test\n");
        kfree(ps2->second_port);
        ps2->second_port = NULL;
    }

    // At-least one port must be working
    if(ps2->first_port != NULL) {
        irq_t irq = x64_pic_irq(1);
        if(irq == NULL_IRQ) {
            kfree(ps2->first_port);
            ps2->first_port = NULL;
            goto first_port_init;
        }

        ps2->first_port->action =
            irq_install_handler(
                    irq_to_desc(irq),
                    NULL,
                    (void*)ps2->first_port,
                    ps2_8042_port_irq_handler);
        dprintk("Installed First PS/2 Port Handler on IRQ (%ld)\n",
                irq);

        if(ps2->first_port->action == NULL) {
            kfree(ps2->first_port);
            ps2->first_port = NULL;
            goto first_port_init;
        } 
        unmask_irq(irq);

        uint8_t cfg;
        res = ps2_8042_read_cfg(ps2, &cfg);
        if(res) {
            mask_irq(irq);
            irq_uninstall_action(ps2->first_port->action);
            kfree(ps2->first_port);
            ps2->first_port = NULL;
            goto first_port_init;
        }
    
        cfg |= (1ULL<<0); // Enable First Port IRQ
    
        res = ps2_8042_write_cfg(ps2, cfg);
        if(res) {
            mask_irq(irq);
            irq_uninstall_action(ps2->first_port->action);
            kfree(ps2->first_port);
            ps2->first_port = NULL;
            goto first_port_init;
        }

        res = ps2_register_port(&ps2->first_port->port);
        if(res) {
            mask_irq(irq);
            irq_uninstall_action(ps2->first_port->action);
            kfree(ps2->first_port);
            ps2->first_port = NULL;
            goto first_port_init;
        }

        dprintk("8042 PS/2: Registered First Port\n");
    }
first_port_init:

    if(ps2->second_port != NULL) {
        irq_t irq = x64_pic_irq(12);
        if(irq == NULL_IRQ) {
            kfree(ps2->second_port);
            ps2->second_port = NULL;
            goto second_port_init;
        }

        ps2->second_port->action =
            irq_install_handler(
                    irq_to_desc(irq),
                    NULL,
                    (void*)ps2->second_port,
                    ps2_8042_port_irq_handler);
        dprintk("Installed Second PS/2 Port Handler on IRQ (%ld)\n",
                irq);

        if(ps2->second_port->action == NULL) {
            kfree(ps2->second_port);
            ps2->second_port = NULL;
            goto second_port_init;
        }
        unmask_irq(irq);

        uint8_t cfg;
        res = ps2_8042_read_cfg(ps2, &cfg);
        if(res) {
            mask_irq(irq);
            irq_uninstall_action(ps2->second_port->action);
            kfree(ps2->second_port);
            ps2->second_port = NULL;
            goto second_port_init;
        }
    
        cfg |= (1ULL<<1); // Enable Second Port IRQ
    
        res = ps2_8042_write_cfg(ps2, cfg);
        if(res) {
            mask_irq(irq);
            irq_uninstall_action(ps2->second_port->action);
            kfree(ps2->second_port);
            ps2->second_port = NULL;
            goto second_port_init;
        }

        res = ps2_register_port(&ps2->second_port->port);
        if(res) {
            mask_irq(irq);
            irq_uninstall_action(ps2->second_port->action);
            kfree(ps2->second_port);
            ps2->second_port = NULL;
            goto second_port_init;
        }
        
        dprintk("8042 PS/2: Registered Second Port\n");
    }
second_port_init:

    if(ps2->first_port == NULL && ps2->second_port == NULL) {
        res = 0;
        printk("8042 PS/2: Neither Port Functional\n");
        goto err3;
    }

    if(ps2->first_port) {
        printk("8042 PS/2: First Port Functional\n");
    }
    if(ps2->second_port) {
        printk("8042 PS/2: Second Port Functional\n");
    }

    return 0;

err3:
    if(ps2->second_port) {
        kfree(ps2->second_port);
    }
err2:
    if(ps2->first_port) {
        kfree(ps2->first_port);
    }
err1:
    kfree(ps2);
err0:
    return 0; // The device is non-functional/non-present
              // this isn't a "failure" to probe
}
declare_init_desc(bus, ps2_8042_probe, "Probing 8042 PS/2 Controller");

