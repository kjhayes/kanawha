
#include <kanawha/dev/input.h>
#include <kanawha/errno.h>
#include <drivers/input/ps2/scanset.h>

#define FLAG_F0 (1ULL<<0)
#define FLAG_E0 (1ULL<<1)

input_key_t simple_key_set[256] = {
    [0x01] = INPUT_KEY_F9,
    [0x03] = INPUT_KEY_F5,
    [0x04] = INPUT_KEY_F3,
    [0x05] = INPUT_KEY_F1,
    [0x06] = INPUT_KEY_F2,
    [0x07] = INPUT_KEY_F12,
    [0x09] = INPUT_KEY_F10,
    [0x0A] = INPUT_KEY_F8,
    [0x0B] = INPUT_KEY_F6,
    [0x0C] = INPUT_KEY_F4,
    [0x0D] = INPUT_KEY_TAB,
    [0x0E] = INPUT_KEY_BACKTICK,
    [0x11] = INPUT_KEY_LALT,
    [0x12] = INPUT_KEY_LSHIFT,
    [0x14] = INPUT_KEY_LCTRL,
    [0x15] = INPUT_KEY_Q,
    [0x16] = INPUT_KEY_1,
    [0x1A] = INPUT_KEY_Z,
    [0x1B] = INPUT_KEY_S,
    [0x1C] = INPUT_KEY_A,
    [0x1D] = INPUT_KEY_W,
    [0x1E] = INPUT_KEY_2,
    [0x21] = INPUT_KEY_C,
    [0x22] = INPUT_KEY_X,
    [0x23] = INPUT_KEY_D,
    [0x24] = INPUT_KEY_E,
    [0x25] = INPUT_KEY_4,
    [0x26] = INPUT_KEY_3,
    [0x29] = INPUT_KEY_SPACE,
    [0x2A] = INPUT_KEY_V,
    [0x2B] = INPUT_KEY_F,
    [0x2C] = INPUT_KEY_T,
    [0x2D] = INPUT_KEY_R,
    [0x2E] = INPUT_KEY_5,
    [0x31] = INPUT_KEY_N,
    [0x32] = INPUT_KEY_B,
    [0x33] = INPUT_KEY_H,
    [0x34] = INPUT_KEY_G,
    [0x35] = INPUT_KEY_Y,
    [0x36] = INPUT_KEY_6,
    [0x3A] = INPUT_KEY_M,
    [0x3B] = INPUT_KEY_J,
    [0x3C] = INPUT_KEY_U,
    [0x3D] = INPUT_KEY_7,
    [0x3E] = INPUT_KEY_8,
    [0x41] = INPUT_KEY_COMMA,
    [0x42] = INPUT_KEY_K,
    [0x43] = INPUT_KEY_I,
    [0x44] = INPUT_KEY_O,
    [0x45] = INPUT_KEY_0,
    [0x46] = INPUT_KEY_9,
    [0x49] = INPUT_KEY_PERIOD,
    [0x4A] = INPUT_KEY_FSLASH,
    [0x4B] = INPUT_KEY_L,
    [0x4C] = INPUT_KEY_SEMICOLON,
    [0x4D] = INPUT_KEY_P,
    [0x4E] = INPUT_KEY_MINUS,
    [0x52] = INPUT_KEY_SINGLE_QUOT,
    [0x54] = INPUT_KEY_OPEN_SQR,
    [0x55] = INPUT_KEY_EQUAL_SIGN,
    [0x58] = INPUT_KEY_CAPSLOCK,
    [0x59] = INPUT_KEY_RSHIFT,
    [0x5A] = INPUT_KEY_ENTER,
    [0x5B] = INPUT_KEY_CLOSE_SQR,
    [0x5D] = INPUT_KEY_BSLASH,
    [0x66] = INPUT_KEY_BACKSPACE,
    [0x69] = INPUT_KEY_NUMPAD_1,
    [0x6B] = INPUT_KEY_NUMPAD_4,
    [0x6C] = INPUT_KEY_NUMPAD_7,
    [0x70] = INPUT_KEY_NUMPAD_0,
    [0x71] = INPUT_KEY_NUMPAD_PERIOD,
    [0x72] = INPUT_KEY_NUMPAD_2,
    [0x73] = INPUT_KEY_NUMPAD_5,
    [0x74] = INPUT_KEY_NUMPAD_6,
    [0x75] = INPUT_KEY_NUMPAD_8,
    [0x76] = INPUT_KEY_ESCAPE,
    [0x77] = INPUT_KEY_NUMLOCK,
    [0x78] = INPUT_KEY_F11,
    [0x79] = INPUT_KEY_NUMPAD_PLUS,
    [0x7A] = INPUT_KEY_NUMPAD_3,
    [0x7B] = INPUT_KEY_NUMPAD_MINUS,
    [0x7C] = INPUT_KEY_NUMPAD_ASTERISK,
    [0x7D] = INPUT_KEY_NUMPAD_9,
    [0x7E] = INPUT_KEY_SCROLLLOCK,
    [0x83] = INPUT_KEY_F7,
};

input_key_t e0_key_set[256] = {
    [0x6B] = INPUT_KEY_LEFT_ARROW,
    [0x74] = INPUT_KEY_RIGHT_ARROW,
    [0x75] = INPUT_KEY_UP_ARROW,
    [0x72] = INPUT_KEY_DOWN_ARROW,
};

static int
qwerty_2_scanset_handler(
        uint8_t next_byte,
        unsigned long *flags,
        struct input_event *out)
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
            out->motion = INPUT_MOTION_RELEASED;
        } else {
            out->motion = INPUT_MOTION_PRESSED;
        }
        *flags = 0;
        return 0;
    } else if (((*flags & FLAG_E0) != 0) && (e0_key_set[next_byte] != 0)) {
        out->key = e0_key_set[next_byte];
        if(*flags & FLAG_F0) {
            out->motion = INPUT_MOTION_RELEASED;
        } else {
            out->motion = INPUT_MOTION_PRESSED;
        }
        *flags = 0;
    }

    // Clear E0 and F0
    *flags &= ~FLAG_F0;
    *flags &= ~FLAG_E0;

    return -EINVAL;
}

struct ps2_kbd_scanset
qwerty_scanset_2 = {
    .handle_scancode = qwerty_2_scanset_handler,
};

