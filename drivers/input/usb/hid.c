
#include <drivers/usb/device.h>
#include <drivers/usb/usb.h>
#include <kanawha/dev/input.h>
#include <kanawha/dma.h>
#include <kanawha/init.h>
#include <kanawha/tasklet.h>

#define USB_HID_NAMEBUFLEN (32)

struct usb_hid_report
{
    uint8_t modifiers;
    uint8_t __resv;
    uint8_t keys[6];
} __packed;

struct usb_hid
{
    struct usb_interface *interface;
    struct periodic_tasklet *poll_event;

    struct input_dev input_dev;

    char name[USB_HID_NAMEBUFLEN];

    dma_addr_t report_dma;
    struct usb_hid_report report;
};

static inline input_key_t
usb_hid_key_to_input_key(uint8_t key)
{
    switch(key)
    {
    case 4:
        return INPUT_KEY_A;
    case 5:
        return INPUT_KEY_B;
    case 6:
        return INPUT_KEY_C;
    case 7:
        return INPUT_KEY_D;
    case 8:
        return INPUT_KEY_E;
    case 9:
        return INPUT_KEY_F;
    case 10:
        return INPUT_KEY_G;
    case 11:
        return INPUT_KEY_H;
    case 12:
        return INPUT_KEY_I;
    case 13:
        return INPUT_KEY_J;
    case 14:
        return INPUT_KEY_K;
    case 15:
        return INPUT_KEY_L;
    case 16:
        return INPUT_KEY_M;
    case 17:
        return INPUT_KEY_N;
    case 18:
        return INPUT_KEY_O;
    case 19:
        return INPUT_KEY_P;
    case 20:
        return INPUT_KEY_Q;
    case 21:
        return INPUT_KEY_R;
    case 22:
        return INPUT_KEY_S;
    case 23:
        return INPUT_KEY_T;
    case 24:
        return INPUT_KEY_U;
    case 25:
        return INPUT_KEY_V;
    case 26:
        return INPUT_KEY_W;
    case 27:
        return INPUT_KEY_X;
    case 28:
        return INPUT_KEY_Y;
    case 29:
        return INPUT_KEY_Z;
    case 30:
        return INPUT_KEY_1;
    case 31:
        return INPUT_KEY_2;
    case 32:
        return INPUT_KEY_3;
    case 33:
        return INPUT_KEY_4;
    case 34:
        return INPUT_KEY_5;
    case 35:
        return INPUT_KEY_6;
    case 36:
        return INPUT_KEY_7;
    case 37:
        return INPUT_KEY_8;
    case 38:
        return INPUT_KEY_9;
    case 39:
        return INPUT_KEY_0;
    case 40:
        return INPUT_KEY_ENTER;
    case 41:
        return INPUT_KEY_ESCAPE;
    case 42:
        return INPUT_KEY_BACKSPACE;
    case 43:
        return INPUT_KEY_TAB;
    case 44:
        return INPUT_KEY_SPACE;
    case 45:
        return INPUT_KEY_MINUS;
    case 46:
        return INPUT_KEY_EQUAL_SIGN;
    case 47:
        return INPUT_KEY_OPEN_SQR;
    case 48:
        return INPUT_KEY_CLOSE_SQR;
    case 49:
        return INPUT_KEY_BSLASH;
    case 51:
        return INPUT_KEY_SEMICOLON;
    case 52:
        return INPUT_KEY_SINGLE_QUOT;
    case 53:
        return INPUT_KEY_BACKTICK;
    case 54:
        return INPUT_KEY_COMMA;
    case 55:
        return INPUT_KEY_PERIOD;
    case 56:
        return INPUT_KEY_FSLASH;
    case 57:
        return INPUT_KEY_CAPSLOCK;
    case 58:
        return INPUT_KEY_F1;
    case 59:
        return INPUT_KEY_F2;
    case 60:
        return INPUT_KEY_F3;
    case 61:
        return INPUT_KEY_F4;
    case 62:
        return INPUT_KEY_F5;
    case 63:
        return INPUT_KEY_F6;
    case 64:
        return INPUT_KEY_F7;
    case 65:
        return INPUT_KEY_F8;
    case 66:
        return INPUT_KEY_F9;
    case 67:
        return INPUT_KEY_F10;
    case 68:
        return INPUT_KEY_F11;
    case 69:
        return INPUT_KEY_F12;
    case 79:
        return INPUT_KEY_RIGHT_ARROW;
    case 80:
        return INPUT_KEY_LEFT_ARROW;
    case 81:
        return INPUT_KEY_DOWN_ARROW;
    case 82:
        return INPUT_KEY_UP_ARROW;
    default:
        return INPUT_KEY_UNKNOWN;
    }
}

static void
usb_hid_handle_key_released(struct usb_hid *hid, uint8_t key)
{
    struct input_event evt;
    evt.key = usb_hid_key_to_input_key(key);
    evt.motion = INPUT_MOTION_RELEASED;
    evt.type = INPUT_EVT_KEY;
    input_driver_enqueue_event(&hid->input_dev, &evt);
}

static void
usb_hid_handle_key_pressed(struct usb_hid *hid, uint8_t key)
{
    struct input_event evt;
    evt.key = usb_hid_key_to_input_key(key);
    evt.motion = INPUT_MOTION_PRESSED;
    evt.type = INPUT_EVT_KEY;
    input_driver_enqueue_event(&hid->input_dev, &evt);
}

static int
usb_hid_handle_polled_report(struct usb_hid *hid, struct usb_hid_report *report)
{
    uint8_t mod_delta = report->modifiers ^ hid->report.modifiers;
    if(mod_delta != 0)
    {
        const input_key_t modifier_keys[8] = {
            INPUT_KEY_LCTRL,
            INPUT_KEY_LSHIFT,
            INPUT_KEY_LALT,
            INPUT_KEY_UNKNOWN, // Left GUI (Windows/Command)
            INPUT_KEY_RCTRL,
            INPUT_KEY_RSHIFT,
            INPUT_KEY_RALT,
            INPUT_KEY_UNKNOWN, // Right GUI (Windows/Command)
        };
        for(int i = 0; i < 8; i++)
        {
            uint8_t mask = 1 << i;
            if(mask & mod_delta)
            {
                struct input_event evt = {0};
                evt.key = modifier_keys[i];
                evt.type = INPUT_EVT_KEY;
                if(mask & report->modifiers)
                {
                    // Press
                    evt.motion = INPUT_MOTION_PRESSED;
                }
                else
                {
                    // Release
                    evt.motion = INPUT_MOTION_RELEASED;
                }
                input_driver_enqueue_event(&hid->input_dev, &evt);
            }
        }
    }

    // check for key releases
    for(int i = 0; i < 6; i++)
    {
        int was_released = 1;
        uint8_t key = hid->report.keys[i];
        if(key == 0)
        {
            continue;
        }
        for(int j = 0; j < 6; j++)
        {
            if(report->keys[j] == key)
            {
                was_released = 0;
                break;
            }
        }
        if(was_released)
        {
            usb_hid_handle_key_released(hid, key);
        }
    }

    // check for key presses
    for(int i = 0; i < 6; i++)
    {
        int was_pressed = 1;
        uint8_t key = report->keys[i];
        if(key == 0)
        {
            continue;
        }
        for(int j = 0; j < 6; j++)
        {
            if(hid->report.keys[j] == key)
            {
                was_pressed = 0;
                break;
            }
        }
        if(was_pressed)
        {
            usb_hid_handle_key_pressed(hid, key);
        }
    }

    hid->report = *report;

    return 0;
}

static void
usb_hid_poll_callback(void *_hid)
{
    int res;
    struct usb_hid *hid = _hid;
    DEBUG_ASSERT(KERNEL_ADDR(hid));
    DEBUG_ASSERT(KERNEL_ADDR(hid->interface));
    DEBUG_ASSERT(KERNEL_ADDR(hid->interface->config));
    DEBUG_ASSERT(KERNEL_ADDR(hid->interface->config->device));

    struct usb_hid_report __phys *report_phys = dma_phys_addr(hid->report_dma);

    res = usb_device_control_transfer(
        hid->interface->config->device,
        USB_ENDPOINT_ID_DEFAULT_CONTROL,
        USB_DEV_CONTROL_REQUEST_TYPE_DIR_DEVICE_TO_HOST |
            USB_DEV_CONTROL_REQUEST_TYPE_CLASS |
            USB_DEV_CONTROL_REQUEST_TYPE_TARGET_INTERFACE,
        0x01,
        0,
        hid->interface->index,
        sizeof(struct usb_hid_report),
        report_phys,
        sizeof(struct usb_hid_report));
    if(res)
    {
        wprintk("USB HID: GET_REPORT failed! (err=%s)\n", errnostr(res));
        return;
    }

    struct usb_hid_report *report = dma_virt_addr(hid->report_dma);
    res = usb_hid_handle_polled_report(hid, report);
    if(res)
    {
        wprintk("USB HID: Failed to handle polled report! (err=%s)\n",
                errnostr(res));
        return;
    }
}

static int
usb_hid_driver_probe_interface(struct usb_interface_driver *driver,
                               struct usb_interface *interface)
{
    if(interface->usb_id.class != 0x3)
    {
        return -EINVAL;
    }
    switch(interface->usb_id.subclass)
    {
    case 0x01: // Boot Subclass
        break;
    case 0x00: // Report Subclass (unsupported)
        wprintk("USB HID Device does not support the Boot Protocol! (cannot "
                "drive)\n");
    default:
        return -EINVAL;
    }
    return 0;
}

static int
usb_hid_driver_init_interface(struct usb_interface_driver *driver,
                              struct usb_interface *interface)
{
    int res;

    printk("USB HID: setting device to boot protocol...\n");

    res = usb_device_control_transfer(
        interface->config->device,
        USB_ENDPOINT_ID_DEFAULT_CONTROL,
        USB_DEV_CONTROL_REQUEST_TYPE_DIR_HOST_TO_DEVICE |
            USB_DEV_CONTROL_REQUEST_TYPE_CLASS |
            USB_DEV_CONTROL_REQUEST_TYPE_TARGET_INTERFACE,
        0x0B, // SetProtocol
        0,
        interface->index,
        0,
        NULL,
        0);
    if(res)
    {
        eprintk("USB HID: Failed to set device to boot protocol! (err=%s)\n",
                errnostr(res));
        return res;
    }

    printk("USB HID: set device to boot protocol\n");

    struct usb_hid *hid = kzmalloc(sizeof(struct usb_hid), KM_KERNEL);
    if(hid == NULL)
    {
        wprintk("USB HID: ran out of memory allocating device structure!\n");
        return -ENOMEM;
    }

    hid->interface = interface;
    interface->driver_priv_state = hid;

    static unsigned int global_id = 0;
    snprintk(hid->name, USB_HID_NAMEBUFLEN, "usb-hid-%u", global_id);
    hid->name[USB_HID_NAMEBUFLEN - 1] = '\0';
    global_id++;

    res = dma_alloc(sizeof(struct usb_hid_report),
                    alignof(struct usb_hid_report),
                    0,
                    &hid->report_dma);

    if(res)
    {
        kfree(hid);
        return res;
    }

    res = register_input_dev(&hid->input_dev, hid->name);
    if(res)
    {
        dma_free(hid->report_dma, sizeof(struct usb_hid_report));
        kfree(hid);
        return res;
    }

    hid->poll_event = tasklet_create_periodic(msec_to_duration(5),
                                              (void *)hid,
                                              usb_hid_poll_callback);
    if(hid->poll_event == NULL)
    {
        unregister_input_dev(&hid->input_dev);
        dma_free(hid->report_dma, sizeof(struct usb_hid_report));
        kfree(hid);
        printk("USB HID: Failed to create periodic tasklet!\n");
        return -ENOMEM;
    }

    return 0;
}

static int
usb_hid_driver_deinit_interface(struct usb_interface_driver *driver,
                                struct usb_interface *interface)
{
    int res;

    struct usb_hid *hid = interface->driver_priv_state;

    tasklet_destroy_periodic(hid->poll_event);
    unregister_input_dev(&hid->input_dev);
    dma_free(hid->report_dma, sizeof(struct usb_hid_report));
    kfree(hid);

    return 0;
}

static struct usb_interface_driver_ops usb_hid_driver_ops = {
    .probe = usb_hid_driver_probe_interface,
    .init = usb_hid_driver_init_interface,
    .deinit = usb_hid_driver_deinit_interface,
};
static struct usb_interface_driver usb_hid_driver = {
    .ops = &usb_hid_driver_ops,
};

static int
usb_hid_driver_register(void)
{
    return register_usb_interface_driver(&usb_hid_driver);
}
declare_init_desc(device,
                  usb_hid_driver_register,
                  "Registering USB HID Driver");
