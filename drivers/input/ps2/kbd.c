
#include <drivers/input/ps2/scanset.h>
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

static atomic_t ps2_kbd_counter = 0;

#define PS2_KBD_NAME_BUFLEN 16
#define PS2_KBD_KEYPRESS_BUFLEN 64
struct ps2_kbd
{
    struct ps2_port *port;

    struct input_dev input_dev;

    unsigned long scanset_state;
    struct ps2_kbd_scanset *scanset;

    char name_buf[PS2_KBD_NAME_BUFLEN];

    unsigned int registered : 1;
};

static int
ps2_kbd_handle_scancode(struct ps2_kbd *kbd, uint8_t scancode)
{
    struct input_event event;

    int res =
        (kbd->scanset->handle_scancode)(scancode, &kbd->scanset_state, &event);

    if(res || event.key == INPUT_KEY_UNKNOWN)
    {
        return 0;
    }

    input_driver_enqueue_event(&kbd->input_dev, &event);
    return 0;
}

static void
ps2_kbd_recv_callback(struct ps2_port *port, void *priv_data, uint8_t recv)
{
    int res;

    struct ps2_kbd *kbd = (struct ps2_kbd *)priv_data;
    if(kbd->registered)
    {
        res = ps2_kbd_handle_scancode(kbd, recv);
        if(res)
        {
            dprintk("ps2_kbd_enqueue_scancode Failed! (lost a key "
                    "event) (err=%s)\n",
                    errnostr(res));
        }
    }
}

static int
ps2_kbd_attach(struct ps2_driver *driver, struct ps2_port *port)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(port));
    DEBUG_ASSERT(KERNEL_ADDR(port->ops));
    DEBUG_ASSERT(KERNEL_ADDR(port->ops->send));
    DEBUG_ASSERT(KERNEL_ADDR(driver));

    struct ps2_kbd *kbd = kzmalloc(sizeof(struct ps2_kbd), KM_KERNEL);
    if(kbd == NULL)
    {
        return -ENOMEM;
    }

    kbd->port = port;
    kbd->scanset = &qwerty_scanset_2;
    kbd->registered = 0;

    ps2_port_set_callback(port, ps2_kbd_recv_callback, (void *)kbd);

    unsigned long id = atomic_fetch_inc(&ps2_kbd_counter);
    snprintk(kbd->name_buf, PS2_KBD_NAME_BUFLEN, "ps2-kbd-%lu", (ul_t)id);
    kbd->name_buf[PS2_KBD_NAME_BUFLEN - 1] = '\0';

    res = register_input_dev(&kbd->input_dev, kbd->name_buf);
    if(res)
    {
        kfree(kbd);
        return res;
    }

    res = ps2_port_enable_scanning(port);
    if(res)
    {
        unregister_input_dev(&kbd->input_dev);
        kfree(kbd);
        return res;
    }

    kbd->registered = 1;

    return 0;
}

static int
ps2_kbd_deattach(struct ps2_driver *driver, struct ps2_port *port)
{
    return -EUNIMPL;
}

static struct ps2_driver_ops ps2_kbd_driver_ops = {
    .attach = ps2_kbd_attach,
    .deattach = ps2_kbd_deattach,
};

static uint8_t model_f_id_0[] = {0xAB, 0x83};
static uint8_t model_f_id_1[] = {0xAB, 0xC1};
static uint8_t short_id[] = {0xAB, 0x84};

static struct ps2_driver ps2_kbd_driver = {

    .ops = &ps2_kbd_driver_ops,

    .num_ids = 3,

    // These ID's are taken from OSDev's list so I'm not 100%
    // sure how accurate it is.
    .ids =
        {
            {
                // AT Keyboard
                .len = 0,
                .id_bytes = NULL,
            },
            {
                // Model F
                .len = sizeof(model_f_id_0),
                .id_bytes = model_f_id_0,
            },
            {
                // Model F (other ID)
                .len = sizeof(model_f_id_1),
                .id_bytes = model_f_id_1,
            },
            {
                // Thinkpads and other "Short Keyboards"
                .len = sizeof(short_id),
                .id_bytes = short_id,
            },

            // There are plenty more but these three should suffice for now
        },
};

static int
ps2_kbd_register_driver(void)
{
    int res;

    ps2_driver_struct_init(&ps2_kbd_driver);

    res = ps2_register_driver(&ps2_kbd_driver);
    if(res)
    {
        return res;
    }
    return 0;
}
declare_init(device, ps2_kbd_register_driver);
