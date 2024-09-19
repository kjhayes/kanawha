
#include <kanawha/init.h>
#include <kanawha/ptree.h>
#include <kanawha/spinlock.h>
#include <kanawha/errno.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/char_dev.h>
#include <kanawha/assert.h>
#include <kanawha/vmem.h>
#include <kanawha/kbd.h>
#include <drivers/ps2/port.h>
#include <drivers/ps2/driver.h>
#include <drivers/ps2/kbd/scanset.h>

static DECLARE_SPINLOCK(ps2_kbd_tree_lock);
static DECLARE_PTREE(ps2_kbd_tree);

#define PS2_KBD_NAME_BUFLEN 16
#define PS2_KBD_KEYPRESS_BUFLEN 64
struct ps2_kbd
{
    struct ps2_port *port;
    struct ptree_node tree_node;

    struct kbd kbd;

    unsigned long scanset_state;
    struct ps2_kbd_scanset *scanset;

    char name_buf[PS2_KBD_NAME_BUFLEN];
};

static int
ps2_kbd_handle_scancode(
        struct ps2_kbd *kbd,
        uint8_t scancode)
{
    struct kbd_event event;

    int res = (kbd->scanset->handle_scancode)(
            scancode,
            &kbd->scanset_state,
            &event);
   
    if(res || event.key == KBD_KEY_UNKNOWN) {
        return 0;
    }

    kbd_enqueue_event(&kbd->kbd, &event);
    return 0;
}

static void
ps2_kbd_recv_callback(
        struct ps2_port *port,
        void *priv_data,
        uint8_t recv)
{
    struct ps2_kbd *kbd = (struct ps2_kbd*)priv_data;
    int res = ps2_kbd_handle_scancode(kbd, recv);
    if(res) {
        wprintk("ps2_kbd_enqueue_scancode Failed! (lost a key event) (err=%s)\n",
                errnostr(res));
    }
}

static int
ps2_kbd_attach(
        struct ps2_driver *driver,
        struct ps2_port *port)
{
    int res;

    printk("ps2_kbd_attach\n");
    
    DEBUG_ASSERT(KERNEL_ADDR(port));
    DEBUG_ASSERT(KERNEL_ADDR(port->ops));
    DEBUG_ASSERT(KERNEL_ADDR(port->ops->send));
    DEBUG_ASSERT(KERNEL_ADDR(driver));

    struct ps2_kbd *kbd = kmalloc(sizeof(struct ps2_kbd));
    if(kbd == NULL) {
        return -ENOMEM;
    }
    memset(kbd, 0, sizeof(struct ps2_kbd));

    kbd->port = port;
    kbd->scanset = &qwerty_scanset_2;

    res = kbd_init_struct(&kbd->kbd);
    if(res) {
        kfree(kbd);
        return res;
    }

    ps2_port_set_callback(
            port,
            ps2_kbd_recv_callback,
            (void*)kbd);

    spin_lock(&ps2_kbd_tree_lock);

    res = ptree_insert_any(&ps2_kbd_tree, &kbd->tree_node);
    if(res) {
        kfree(kbd);
        spin_unlock(&ps2_kbd_tree_lock);
        return res;
    }

    uintptr_t id = kbd->tree_node.key;
    snprintk(kbd->name_buf, PS2_KBD_NAME_BUFLEN, "ps2-kbd-%llu", (ull_t)id);
    kbd->name_buf[PS2_KBD_NAME_BUFLEN-1] = '\0';

    res = register_kbd(&kbd->kbd, kbd->name_buf);
    if(res) {
        ptree_remove(&ps2_kbd_tree, kbd->tree_node.key);
        kfree(kbd);
        spin_unlock(&ps2_kbd_tree_lock);
        return res;
    }

    res = ps2_port_enable_scanning(port);
    if(res) {
        ptree_remove(&ps2_kbd_tree, kbd->tree_node.key);
        kfree(kbd);
        spin_unlock(&ps2_kbd_tree_lock);
        return res;
    }

    spin_unlock(&ps2_kbd_tree_lock);

    return 0;
}

static int
ps2_kbd_deattach(
        struct ps2_driver *driver,
        struct ps2_port *port)
{
    return -EUNIMPL;
}

static struct ps2_driver_ops
ps2_kbd_driver_ops = {
    .attach = ps2_kbd_attach,
    .deattach = ps2_kbd_deattach,
};

static uint8_t model_f_id_0[] = {
    0xAB, 0x83
};
static uint8_t model_f_id_1[] = {
    0xAB, 0xC1
};
static uint8_t short_id[] = {
    0xAB, 0x84
};

static struct ps2_driver
ps2_kbd_driver = {

    .ops = &ps2_kbd_driver_ops,

    .num_ids = 3,

    // These ID's are taken from OSDev's list so I'm not 100%
    // sure how accurate it is.
    .ids = {
        { // AT Keyboard
            .len = 0,
            .id_bytes = NULL,
        },
        { // Model F
            .len = sizeof(model_f_id_0),
            .id_bytes = model_f_id_0,
        },
        { // Model F (other ID)
            .len = sizeof(model_f_id_1),
            .id_bytes = model_f_id_1,
        },
        { // Thinkpads and other "Short Keyboards"
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
    if(res) {
        return res;
    }
    return 0;
}
declare_init(device, ps2_kbd_register_driver);

