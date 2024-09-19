
#include <kanawha/kbd.h>
#include <kanawha/errno.h>
#include <drivers/ps2/kbd/scanset.h>

#define FLAG_F0 (1ULL<<0)
#define FLAG_E0 (1ULL<<1)

kbd_key_t simple_key_set[256] = {
    [0x01] = KBD_KEY_F9,
    [0x03] = KBD_KEY_F5,
    [0x04] = KBD_KEY_F3,
    [0x05] = KBD_KEY_F1,
    [0x06] = KBD_KEY_F2,
    [0x07] = KBD_KEY_F12,
    [0x09] = KBD_KEY_F10,
    [0x0A] = KBD_KEY_F8,
    [0x0B] = KBD_KEY_F6,
    [0x0C] = KBD_KEY_F4,
    [0x0D] = KBD_KEY_TAB,
    [0x0E] = KBD_KEY_BACKTICK,
    [0x11] = KBD_KEY_LALT,
    [0x12] = KBD_KEY_LSHIFT,
    [0x14] = KBD_KEY_LCTRL,
    [0x15] = KBD_KEY_Q,
    [0x16] = KBD_KEY_1,
    [0x1A] = KBD_KEY_Z,
    [0x1B] = KBD_KEY_S,
    [0x1C] = KBD_KEY_A,
    [0x1D] = KBD_KEY_W,
    [0x1E] = KBD_KEY_2,
    [0x21] = KBD_KEY_C,
    [0x22] = KBD_KEY_X,
    [0x23] = KBD_KEY_D,
    [0x24] = KBD_KEY_E,
    [0x25] = KBD_KEY_4,
    [0x26] = KBD_KEY_3,
    [0x29] = KBD_KEY_SPACE,
    [0x2A] = KBD_KEY_V,
    [0x2B] = KBD_KEY_F,
    [0x2C] = KBD_KEY_T,
    [0x2D] = KBD_KEY_R,
    [0x2E] = KBD_KEY_5,
    [0x31] = KBD_KEY_N,
    [0x32] = KBD_KEY_B,
    [0x33] = KBD_KEY_H,
    [0x34] = KBD_KEY_G,
    [0x35] = KBD_KEY_Y,
    [0x36] = KBD_KEY_6,
    [0x3A] = KBD_KEY_M,
    [0x3B] = KBD_KEY_J,
    [0x3C] = KBD_KEY_U,
    [0x3D] = KBD_KEY_7,
    [0x3E] = KBD_KEY_8,
    [0x41] = KBD_KEY_COMMA,
    [0x42] = KBD_KEY_K,
    [0x43] = KBD_KEY_I,
    [0x44] = KBD_KEY_O,
    [0x45] = KBD_KEY_0,
    [0x46] = KBD_KEY_9,
    [0x49] = KBD_KEY_PERIOD,
    [0x4A] = KBD_KEY_FSLASH,
    [0x4B] = KBD_KEY_L,
    [0x4C] = KBD_KEY_SEMICOLON,
    [0x4D] = KBD_KEY_P,
    [0x4E] = KBD_KEY_MINUS,
    [0x52] = KBD_KEY_SINGLE_QUOT,
    [0x54] = KBD_KEY_OPEN_SQR,
    [0x55] = KBD_KEY_EQUAL_SIGN,
    [0x58] = KBD_KEY_CAPSLOCK,
    [0x59] = KBD_KEY_RSHIFT,
    [0x5A] = KBD_KEY_ENTER,
    [0x5B] = KBD_KEY_CLOSE_SQR,
    [0x5D] = KBD_KEY_BSLASH,
    [0x66] = KBD_KEY_BACKSPACE,
    [0x69] = KBD_KEY_NUMPAD_1,
    [0x6B] = KBD_KEY_NUMPAD_4,
    [0x6C] = KBD_KEY_NUMPAD_7,
    [0x70] = KBD_KEY_NUMPAD_0,
    [0x71] = KBD_KEY_NUMPAD_PERIOD,
    [0x72] = KBD_KEY_NUMPAD_2,
    [0x73] = KBD_KEY_NUMPAD_5,
    [0x74] = KBD_KEY_NUMPAD_6,
    [0x75] = KBD_KEY_NUMPAD_8,
    [0x76] = KBD_KEY_ESCAPE,
    [0x77] = KBD_KEY_NUMLOCK,
    [0x78] = KBD_KEY_F11,
    [0x79] = KBD_KEY_NUMPAD_PLUS,
    [0x7A] = KBD_KEY_NUMPAD_3,
    [0x7B] = KBD_KEY_NUMPAD_MINUS,
    [0x7C] = KBD_KEY_NUMPAD_ASTERISK,
    [0x7D] = KBD_KEY_NUMPAD_9,
    [0x7E] = KBD_KEY_SCROLLLOCK,
    [0x83] = KBD_KEY_F7,
};

static int
qwerty_2_scanset_handler(
        uint8_t next_byte,
        unsigned long *flags,
        struct kbd_event *out)
{
    if(next_byte == 0xF0) {
        *flags |= FLAG_F0;
        return -EAGAIN;
    }
    if(next_byte == 0xE0) {
        *flags |= FLAG_E0;
        return -EAGAIN;
    }

    if(((*flags & FLAG_E0) == 0) && (simple_key_set[next_byte] != 0)) {
        out->key = simple_key_set[next_byte];
        if(*flags & FLAG_F0) {
            out->motion = KBD_MOTION_RELEASED;
        } else {
            out->motion = KBD_MOTION_PRESSED;
        }
        *flags = 0;
        return 0;
    }

    return -EINVAL;
}

struct ps2_kbd_scanset
qwerty_scanset_2 = {
    .handle_scancode = qwerty_2_scanset_handler,
};

