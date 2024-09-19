
#include <kanawha/errno.h>
#include <kanawha/spinlock.h>
#include <kanawha/list.h>
#include <kanawha/clk.h>
#include <kanawha/stddef.h>
#include <drivers/ps2/port.h>
#include <drivers/ps2/driver.h>

static DECLARE_SPINLOCK(ps2_global_lock);
static DECLARE_ILIST(ps2_driver_list);
static DECLARE_ILIST(ps2_open_port_list);
static DECLARE_ILIST(ps2_driven_port_list);

static DECLARE_SPINLOCK(ps2_timeout_lock);

// All of the "recv_timeout" related data and functions need
// to be used with the ps2_global_lock held
// (e.g. configuring a generic "unknown" ps2 device(s) needs to be done one at a time)
#define PS2_RECV_TIMEOUT_BUFSIZE 64

static struct {

    int buf_head;
    int buf_tail;
    uint8_t buffer[PS2_RECV_TIMEOUT_BUFSIZE];

} __ps2_recv_timeout_info;

static int
__ps2_recv_timeout_buffer_push(
        uint8_t data)
{
    if(((__ps2_recv_timeout_info.buf_head + 1) % PS2_RECV_TIMEOUT_BUFSIZE)
            == __ps2_recv_timeout_info.buf_tail) {
        return -ENOMEM;
    }

    __ps2_recv_timeout_info.buffer[__ps2_recv_timeout_info.buf_head] = data;
    __ps2_recv_timeout_info.buf_head =
        (__ps2_recv_timeout_info.buf_head + 1) % PS2_RECV_TIMEOUT_BUFSIZE;
    return 0;
}

static int
__ps2_recv_timeout_buffer_pop(
        uint8_t *recv)
{
    if(__ps2_recv_timeout_info.buf_head == __ps2_recv_timeout_info.buf_tail) {
        return -ENXIO;
    }

    *recv = __ps2_recv_timeout_info.buffer[__ps2_recv_timeout_info.buf_tail];
    __ps2_recv_timeout_info.buf_tail =
        (__ps2_recv_timeout_info.buf_tail + 1) % PS2_RECV_TIMEOUT_BUFSIZE;
    return 0;
}

static void
ps2_port_recv_timeout_callback(
        struct ps2_port *port,
        void *__resv, // Cannot touch this
        uint8_t data)
{
    int res = __ps2_recv_timeout_buffer_push(data);
    if(res) {
        wprintk("PS/2 Timeout Buffer Filled Up (Missed a Byte) (err=%s)\n",
                errnostr(res));
    }
}

static int
ps2_port_recv_timeout_clear(void)
{
    // Clear the ring buffer
    __ps2_recv_timeout_info.buf_head = __ps2_recv_timeout_info.buf_tail;
    return 0;
}

static int
ps2_port_recv_timeout(
        uint8_t *data,
        duration_t duration,
        ssize_t attempts)
{
    int res;

    do {
        res = __ps2_recv_timeout_buffer_pop(data);
        if(res == 0) {
            return 0;
        }
        clk_delay(duration);
        attempts--;

    } while(attempts > 0);

    return res;
}

static int
ps2_reset(
        struct ps2_port *port)
{
    int res;

    res = ps2_port_disable_scanning(port);
    if(res) {
        eprintk("ps2_port_disable_scanning failed (err=%s)\n",
                errnostr(res));
        return res;
    }

    spin_lock(&ps2_timeout_lock);
    ps2_recv_callback_f *old_callback = port->callback;
    port->callback = ps2_port_recv_timeout_callback;

    // Reset the Device
    ps2_port_recv_timeout_clear();

    res = ps2_port_send(port, 0xFF);
    if(res) {
        goto err0;
    }

    uint8_t recv; 
    res = ps2_port_recv_timeout(
            &recv,
            msec_to_duration(1),
            10);
    if(res) {
        // No response -> no device
        res = -ENODEV;
        goto err0;
    }

    if(recv == 0xFA || recv == 0xAA) {
        // Good response
    } else if(recv == 0xFC) {
        // Correct "self-test failed" return
        res = -EINVAL;
        goto err0;
    } else {
        // Unexpected
        res = -EINVAL;
        goto err0;
    }

    res = ps2_port_recv_timeout(
            &recv,
            msec_to_duration(1),
            10);
    if(res) {
        goto err0;
    }

    if(recv == 0xFA || recv == 0xAA) {
        // Good response
    } else {
        res = -EINVAL;
        goto err0;
    }

    do {
        res = ps2_port_recv_timeout(
                &recv,
                msec_to_duration(1),
                10);
        if(res) {
            // Wait until we cannot read any more
            break;
        }
    } while(1);

    port->callback = old_callback;
    spin_unlock(&ps2_timeout_lock);

    return 0;

err0:
    port->callback = old_callback;
    spin_unlock(&ps2_timeout_lock);
    return res;
}

static int
ps2_identify(
        struct ps2_port *port,
        uint8_t *buffer,
        size_t *buflen_out_idlen)
{
    int res;

    res = ps2_port_disable_scanning(port);
    if(res) {
        eprintk("ps2_port_disable_scanning failed (err=%s)\n",
                errnostr(res));
        return res;
    }

    spin_lock(&ps2_timeout_lock);

    size_t buflen = *buflen_out_idlen;

    ps2_recv_callback_f *old_callback = port->callback;
    port->callback = ps2_port_recv_timeout_callback;

    // Reset the Device
    ps2_port_recv_timeout_clear();

    res = ps2_port_send(port, 0xF2);
    if(res) {
        goto err0;
    }

    do {
        uint8_t ack;
        res = ps2_port_recv_timeout(
                &ack,
                msec_to_duration(1),
                10);
        if(res) {
            goto err0;
        }

        if(ack == 0xFE) {
            // RESEND
            continue;
        }

        if(ack == 0xFA) {
            break;
        }

        res = -EINVAL;
        goto err0;
    } while(1);

    size_t id_len = 0;
    do {
        uint8_t recv; 
        res = ps2_port_recv_timeout(
                &recv,
                msec_to_duration(1),
                10);
        if(res) {
            break;
        }

        buffer[id_len] = recv;
        id_len++;

        if(id_len == buflen) {
            break;
        }

    } while(1);
  
    // Make sure the ID wasn't longer than the buffer
    if(id_len == buflen) {
        uint8_t extra_byte;
        res = ps2_port_recv_timeout(
                    &extra_byte,
                    msec_to_duration(1),
                    10);
        if(res == 0) {
            eprintk("PS/2 Device ID Was Longer Than Provided Buffer (buflen=0x%llx)\n",
                    (ull_t)buflen);
            return -EINVAL;
        }
    }

    *buflen_out_idlen = id_len;

    port->callback = old_callback;
    spin_unlock(&ps2_timeout_lock);
    return 0;

err0:
    port->callback = old_callback;
    spin_unlock(&ps2_timeout_lock);
    return res;
}

// Returns 1 on match, otherwise 0
static int
ps2_ids_match(
        uint8_t *id_bytes,
        size_t num_id_bytes,
        struct ps2_dev_id *ids,
        size_t num_ids)
{
    for(size_t i = 0; i < num_ids; i++) {
        struct ps2_dev_id *id = ids + i;
        if(id->len != num_id_bytes) {
            continue;
        }

        for(size_t byte_index = 0; byte_index < num_id_bytes; byte_index++) {
            if(id_bytes[byte_index] != id->id_bytes[byte_index]) {
                continue;
            }
        }

        // MATCH!
        return 1;
    }

    return 0;
}

int
ps2_register_port(
        struct ps2_port *port)
{
    int res;

    port->has_driver = 0;
    port->callback = NULL;

    res = ps2_reset(port);
    if(res) {
        wprintk("ps2_reset failed (err=%s)\n",
                errnostr(res));
    }

    // The reset might have enabled scanning again
    res = ps2_port_disable_scanning(port);
    if(res) {
        wprintk("ps2_port_disable_scanning failed (err=%s)\n",
                errnostr(res));
    }

#define IDBUFSIZE 32
    uint8_t id_bytes[IDBUFSIZE];
    size_t num_id_bytes = IDBUFSIZE;

    res = ps2_identify(port, id_bytes, &num_id_bytes);
    if(res) {
        return res;
    }
#undef IDBUFSIZE

    printk("Registering PS/2 Port with Device ID Bytes {");
    if(num_id_bytes > 0) {
        printk("0x%x", id_bytes[0]);
    }
    for(size_t i = 1; i < num_id_bytes; i++) {
        printk(", 0x%x", id_bytes[i]);
    }
    printk("}\n");

    spin_lock(&ps2_global_lock);

    ilist_node_t *driver_node;
    ilist_for_each(driver_node, &ps2_driver_list)
    {
        struct ps2_driver *driver =
            container_of(driver_node, struct ps2_driver, global_node);

        if(ps2_ids_match(
                    id_bytes,
                    num_id_bytes,
                    driver->ids,
                    driver->num_ids))
        {
            res = ps2_driver_attach(
                    driver,
                    port);
            if(res) {
                port->has_driver = 0;
                continue;
            }

            port->has_driver = 1;
            ilist_push_tail(&driver->ports, &port->driver_node);
            ilist_push_tail(&ps2_driven_port_list, &port->global_node);
            break;
        }
    }

    if(!port->has_driver) {
        ilist_push_tail(&ps2_open_port_list, &port->global_node);
    }

    spin_unlock(&ps2_global_lock);

    return 0;
}

int
ps2_unregister_port(
        struct ps2_port *port)
{
    spin_lock(&ps2_global_lock);

    if(port->has_driver) {
        // TODO notify the driver that the port is going away
        ilist_remove(&ps2_driven_port_list, &port->global_node);
        port->has_driver = 0;
    } else {
        ilist_remove(&ps2_open_port_list, &port->global_node);
    }

    spin_unlock(&ps2_global_lock);
    return -EUNIMPL;
}


int
ps2_register_driver(
        struct ps2_driver *driver)
{
    int res;

    spin_lock(&ps2_global_lock);

    ilist_push_tail(&ps2_driver_list, &driver->global_node);

    // Look for any ports which this driver could drive

    ilist_node_t *port_node;
    ilist_for_each(port_node, &ps2_open_port_list) {

        struct ps2_port *port =
            container_of(port_node, struct ps2_port, global_node);

#define IDBUFSIZE 32
        uint8_t id_bytes[IDBUFSIZE];
        size_t num_id_bytes = IDBUFSIZE;

        // We can't give up the lock in the middle of this
        res = ps2_identify(port, id_bytes, &num_id_bytes);
        if(res) {
            return res;
        }
#undef IDBUFSIZE

        if(ps2_ids_match(
                    id_bytes,
                    num_id_bytes,
                    driver->ids,
                    driver->num_ids))
        {
            res = ps2_driver_attach(
                    driver,
                    port);
            if(res) {
                continue;
            }

            ilist_push_tail(&driver->ports, &port->driver_node);
        }
    }

    ilist_for_each(port_node, &driver->ports) {
        struct ps2_port *port =
            container_of(port_node, struct ps2_port, driver_node);
        port->has_driver = 1;
        ilist_remove(&ps2_open_port_list, &port->global_node);
        ilist_push_tail(&ps2_driven_port_list, &port->global_node);
    }

    spin_unlock(&ps2_global_lock);
    return 0;
}
int
ps2_unregister_driver(
        struct ps2_driver *driver)
{
    spin_lock(&ps2_global_lock);

    ilist_remove(&ps2_driver_list, &driver->global_node);

    ilist_node_t *port_node;
    ilist_for_each(port_node, &driver->ports)
    {
        struct ps2_port *port =
            container_of(port_node, struct ps2_port, driver_node);

        port->has_driver = 0;
        port->callback = NULL;
        ilist_remove(&ps2_driven_port_list, &port->global_node);
        ilist_push_tail(&ps2_open_port_list, &port->global_node);
    }

    ilist_remove_all(&driver->ports);

    return 0;
}

int
ps2_port_set_callback(
        struct ps2_port *port,
        ps2_recv_callback_f *func,
        void *priv_data)
{
    port->callback_data = priv_data;
    port->callback = func;
    return 0;
}

int
ps2_port_enable_scanning(
        struct ps2_port *port)
{
    int res;

    spin_lock(&ps2_timeout_lock);
    ps2_recv_callback_f *old_callback = port->callback;
    port->callback = ps2_port_recv_timeout_callback;

    // Reset the Device
    ps2_port_recv_timeout_clear();

    do {
        res = ps2_port_send(port, 0xF4);
        if(res) {
            goto err0;
        }
        uint8_t ack;
        res = ps2_port_recv_timeout(
                &ack,
                msec_to_duration(1),
                10);
        if(res) {
            goto err0;
        }

        if(ack == 0xFA) {
            // ACK
            break;
        } else if(ack == 0xFE) {
            // RESEND
            continue;
        } else {
            // Unexpected
            res = -EINVAL;
            goto err0;
        }

    } while(1);

    port->callback = old_callback;
    spin_unlock(&ps2_timeout_lock);
    return 0;

err0:
    port->callback = old_callback;
    spin_unlock(&ps2_timeout_lock);
    return res;
}

int
ps2_port_disable_scanning(
        struct ps2_port *port)
{
    int res;

    spin_lock(&ps2_timeout_lock);
    ps2_recv_callback_f *old_callback = port->callback;
    port->callback = ps2_port_recv_timeout_callback;

    // Reset the Device
    ps2_port_recv_timeout_clear();

    do {
        res = ps2_port_send(port, 0xF5);
        if(res) {
            goto err0;
        }
        uint8_t ack;
        res = ps2_port_recv_timeout(
                &ack,
                msec_to_duration(1),
                10);
        if(res) {
            goto err0;
        }

        if(ack == 0xFA) {
            // ACK
            break;
        } else if(ack == 0xFE) {
            // RESEND
            continue;
        } else {
            // Unexpected
            res = -EINVAL;
            goto err0;
        }

    } while(1);

    port->callback = old_callback;
    spin_unlock(&ps2_timeout_lock);
    return 0;

err0:
    port->callback = old_callback;
    spin_unlock(&ps2_timeout_lock);
    return res;
}

