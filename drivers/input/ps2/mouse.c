
#include <drivers/ps2/driver.h>
#include <drivers/ps2/port.h>
#include <kanawha/assert.h>
#include <kanawha/atomic.h>
#include <kanawha/dev/input.h>
#include <kanawha/errno.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/ptree.h>
#include <kanawha/string.h>
#include <kanawha/vmem.h>

static atomic_t ps2_mouse_counter = 0;

#define PS2_MOUSE_NAME_BUFLEN 16
#define PS2_MOUSE_EVENT_BUFLEN 64
struct ps2_mouse
{
    struct ps2_port *port;
    struct ptree_node tree_node;

    struct input_dev input_dev;

    char name_buf[PS2_MOUSE_NAME_BUFLEN];

    spinlock_t recv_lock;
    unsigned recv_count;
    uint8_t recv_buffer[2];

    unsigned int registered : 1;
};

static void
ps2_mouse_recv_callback(struct ps2_port *port, void *priv_data, uint8_t recv)
{
    int res;

    struct ps2_mouse *mouse = (struct ps2_mouse *)priv_data;
    if(mouse->registered)
    {
        spin_lock(&mouse->recv_lock);
        if(mouse->recv_count >= 2)
        {
            mouse->recv_count = 0;
            uint8_t flags = mouse->recv_buffer[0];
            uint8_t x_raw = mouse->recv_buffer[1];
            uint8_t y_raw = recv;
            mbarrier();
            spin_unlock(&mouse->recv_lock);

            int delta_x = (int)x_raw - (((int)flags << 4) & 0x100);
            int delta_y = (int)y_raw - (((int)flags << 3) & 0x100);

            struct input_event evt;
            evt.type = INPUT_EVT_MOUSE;
            evt.mouse_delta_x = delta_x;
            evt.mouse_delta_y = delta_y;

            dprintk("PS/2 Mouse Event! (%d,%d)\n", delta_x, delta_y);

            if(delta_x != 0 && delta_y != 0) {
                input_driver_enqueue_event(&mouse->input_dev, &evt);
            }

            if(flags & (1<<0)) {
                // Left mouse button pressed
                struct input_event evt = {
                    .type = INPUT_EVT_KEY,
                    .key = INPUT_KEY_MOUSE_LEFT,
                    .motion = INPUT_MOTION_PRESSED,
                };
                input_driver_enqueue_event(&mouse->input_dev, &evt);
            }
            if(flags & (1<<1)) {
                // Right mouse button pressed
                struct input_event evt = {
                    .type = INPUT_EVT_KEY,
                    .key = INPUT_KEY_MOUSE_RIGHT,
                    .motion = INPUT_MOTION_PRESSED,
                };
                input_driver_enqueue_event(&mouse->input_dev, &evt);
            }
            if(flags & (1<<2)) {
                // Middle mouse button pressed
                struct input_event evt = {
                    .type = INPUT_EVT_KEY,
                    .key = INPUT_KEY_MOUSE_MIDDLE,
                    .motion = INPUT_MOTION_PRESSED,
                };
                input_driver_enqueue_event(&mouse->input_dev, &evt);
            }
        }
        else
        {
            mouse->recv_buffer[mouse->recv_count] = recv;
            mouse->recv_count++;
            spin_unlock(&mouse->recv_lock);
        }
    }
}

static int
ps2_mouse_attach(struct ps2_driver *driver, struct ps2_port *port)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(port));
    DEBUG_ASSERT(KERNEL_ADDR(port->ops));
    DEBUG_ASSERT(KERNEL_ADDR(port->ops->send));
    DEBUG_ASSERT(KERNEL_ADDR(driver));

    struct ps2_mouse *mouse = kzmalloc(sizeof(struct ps2_mouse), KM_KERNEL);
    if(mouse == NULL)
    {
        return -ENOMEM;
    }

    mouse->port = port;
    mouse->registered = 0;

    spinlock_init(&mouse->recv_lock);
    mouse->recv_count = 0;

    ps2_port_set_callback(port, ps2_mouse_recv_callback, (void *)mouse);

    unsigned long id = atomic_fetch_inc(&ps2_mouse_counter);
    snprintk(mouse->name_buf, PS2_MOUSE_NAME_BUFLEN, "ps2-mouse-%lu", (ul_t)id);
    mouse->name_buf[PS2_MOUSE_NAME_BUFLEN - 1] = '\0';

    res = register_input_dev(&mouse->input_dev, mouse->name_buf);
    if(res)
    {
        kfree(mouse);
        return res;
    }

    res = ps2_port_enable_scanning(port);
    if(res)
    {
        unregister_input_dev(&mouse->input_dev);
        kfree(mouse);
        return res;
    }

    mouse->registered = 1;
    port->driver_priv_state = mouse;

    return 0;
}

static int
ps2_mouse_deattach(struct ps2_driver *driver, struct ps2_port *port)
{
    int res;

    struct ps2_mouse *mouse = port->driver_priv_state;
    DEBUG_ASSERT(KERNEL_ADDR(mouse));

    res = ps2_port_disable_scanning(port);
    if(res) {
        wprintk("PS/2 Mouse: Failed to disable port scanning on deattach! (err=%s)\n",
                errnostr(res));
    }

    res = unregister_input_dev(&mouse->input_dev);
    if(res) {
        panic("PS/2 Mouse: Failed to unregister input_dev on deattach! (err=%s)\n",
                errnostr(res));
    }

    kfree(mouse);

    return 0;
}

static struct ps2_driver_ops ps2_mouse_driver_ops = {
    .attach = ps2_mouse_attach,
    .deattach = ps2_mouse_deattach,
};

static uint8_t standard_mouse[] = {0x00};
static uint8_t mouse_with_scroll_wheel[] = {0x03};
static uint8_t five_button_mouse[] = {0x04};

static struct ps2_driver ps2_mouse_driver = {

    .ops = &ps2_mouse_driver_ops,

    .num_ids = 3,

    .ids =
        {
            {
                .len = sizeof(standard_mouse),
                .id_bytes = standard_mouse,
            },
            {
                .len = sizeof(mouse_with_scroll_wheel),
                .id_bytes = mouse_with_scroll_wheel,
            },
            {
                .len = sizeof(five_button_mouse),
                .id_bytes = five_button_mouse,
            },
        },
};

static int
ps2_mouse_register_driver(void)
{
    int res;

    ps2_driver_struct_init(&ps2_mouse_driver);

    res = ps2_register_driver(&ps2_mouse_driver);
    if(res)
    {
        return res;
    }
    return 0;
}
declare_init(device, ps2_mouse_register_driver);
