#ifndef __KANAWHA__INPUT_LINUX_H__
#define __KANAWHA__INPUT_LINUX_H__

#include <kanawha/dev/input.h>

#define LINUX_EV_TYPE_SYN			(0x00)
#define LINUX_EV_TYPE_KEY			(0x01)
#define LINUX_EV_TYPE_REL			(0x02)
#define LINUX_EV_TYPE_ABS			(0x03)
#define LINUX_EV_TYPE_MSC			(0x04)
#define LINUX_EV_TYPE_SW			(0x05)
#define LINUX_EV_TYPE_LED			(0x11)
#define LINUX_EV_TYPE_SND			(0x12)
#define LINUX_EV_TYPE_REP			(0x14)
#define LINUX_EV_TYPE_FF			(0x15)
#define LINUX_EV_TYPE_PWR			(0x16)
#define LINUX_EV_TYPE_FF_STATUS		(0x17)

#define LINUX_EV_KEY_XLIST(X, ...)\
X(LINUX_EV_KEY_0,           (11),  INPUT_KEY_0,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_1,           (2),   INPUT_KEY_1,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_2,           (3),   INPUT_KEY_2,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_3,           (4),   INPUT_KEY_3,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_4,           (5),   INPUT_KEY_4,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_5,           (6),   INPUT_KEY_5,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_6,           (7),   INPUT_KEY_6,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_7,           (8),   INPUT_KEY_7,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_8,           (9),   INPUT_KEY_8,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_9,           (10),  INPUT_KEY_9,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_A,           (30),  INPUT_KEY_A,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_B,           (48),  INPUT_KEY_B,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_C,           (46),  INPUT_KEY_C,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_D,           (32),  INPUT_KEY_D,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_E,           (18),  INPUT_KEY_E,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_F,           (33),  INPUT_KEY_F,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_G,           (34),  INPUT_KEY_G,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_H,           (35),  INPUT_KEY_H,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_I,           (23),  INPUT_KEY_I,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_J,           (36),  INPUT_KEY_J,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_K,           (37),  INPUT_KEY_K,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_L,           (38),  INPUT_KEY_L,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_M,           (50),  INPUT_KEY_M,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_N,           (49),  INPUT_KEY_N,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_O,           (24),  INPUT_KEY_O,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_P,           (25),  INPUT_KEY_P,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_Q,           (16),  INPUT_KEY_Q,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_R,           (19),  INPUT_KEY_R,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_S,           (31),  INPUT_KEY_S,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_T,           (20),  INPUT_KEY_T,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_U,           (22),  INPUT_KEY_U,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_V,           (47),  INPUT_KEY_V,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_W,           (17),  INPUT_KEY_W,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_X,           (45),  INPUT_KEY_X,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_Y,           (21),  INPUT_KEY_Y,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_Z,           (44),  INPUT_KEY_Z,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_ESC,         (1),   INPUT_KEY_ESCAPE,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_MINUS,       (12),  INPUT_KEY_MINUS,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_EQUAL,       (13),  INPUT_KEY_EQUAL_SIGN,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_BACKSPACE,   (14),  INPUT_KEY_BACKSPACE,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_TAB,         (15),  INPUT_KEY_TAB,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_LEFTBRACE,   (26),  INPUT_KEY_OPEN_SQR,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_RIGHTBRACE,  (27),  INPUT_KEY_CLOSE_SQR,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_ENTER,       (28),  INPUT_KEY_ENTER,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_LEFTCTRL,    (29),  INPUT_KEY_LCTRL,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_SEMICOLON,   (39),  INPUT_KEY_SEMICOLON,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_APOSTROPHE,  (40),  INPUT_KEY_SINGLE_QUOT,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_GRAVE,       (41),  INPUT_KEY_BACKTICK,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_LEFTSHIFT,   (42),  INPUT_KEY_LSHIFT,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_BACKSLASH,   (43),  INPUT_KEY_BSLASH,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_COMMA,       (51),  INPUT_KEY_COMMA,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_DOT,         (52),  INPUT_KEY_PERIOD,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_SLASH,       (53),  INPUT_KEY_FSLASH,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_RIGHTSHIFT,  (54),  INPUT_KEY_RSHIFT,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_LEFTALT,     (56),  INPUT_KEY_LALT,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_SPACE,       (57),  INPUT_KEY_SPACE,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_CAPSLOCK,    (58),  INPUT_KEY_CAPSLOCK,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_F1,          (59),  INPUT_KEY_F1,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_F2,          (60),  INPUT_KEY_F2,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_F3,          (61),  INPUT_KEY_F3,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_F4,          (62),  INPUT_KEY_F4,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_F5,          (63),  INPUT_KEY_F5,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_F6,          (64),  INPUT_KEY_F6,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_F7,          (65),  INPUT_KEY_F7,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_F8,          (66),  INPUT_KEY_F8,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_F9,          (67),  INPUT_KEY_F9,  ##__VA_ARGS__)\
X(LINUX_EV_KEY_F10,         (68),  INPUT_KEY_F10,  ##__VA_ARGS__)\

#define LINUX_EV_KEY_VALUE_PRESSED  (1)
#define LINUX_EV_KEY_VALUE_RELEASED (0)
#define LINUX_EV_KEY_VALUE_REPEATED (2)

static inline int
input_key_event_from_linux(
        uint16_t type,
        uint16_t code,
        uint32_t value,
        struct input_event *out)
{
    input_motion_t motion;
    switch(value) {
        case LINUX_EV_KEY_VALUE_PRESSED:
            motion = INPUT_MOTION_PRESSED;
            break;
        case LINUX_EV_KEY_VALUE_RELEASED:
            motion = INPUT_MOTION_RELEASED;
            break;
        case LINUX_EV_KEY_VALUE_REPEATED:
            motion = INPUT_MOTION_HELD;
            break;
        default:
            return -EINVAL;
    }

    input_key_t key;
    switch(code)
    {
#define LINUX_EV_KEY_CODE_CASE(__LINUX_NAME, __LINUX_VALUE, __KANAWHA_ENUM, ...)\
        case __LINUX_VALUE: key = __KANAWHA_ENUM; break;
        LINUX_EV_KEY_XLIST(LINUX_EV_KEY_CODE_CASE)
#undef LINUX_EV_KEY_CODE_CASE
        default:
            return -EUNIMPL;
    }

    if(key == INPUT_KEY_UNKNOWN) {
        return -EUNIMPL;
    }

    out->type = INPUT_EVT_KEY;
    out->motion = motion;
    out->key = key;
    return 0;
}

static inline int
input_event_from_linux(
        uint16_t type,
        uint16_t code,
        uint32_t value,
        struct input_event *out)
{
    switch(type) {
        case LINUX_EV_TYPE_KEY:
            return input_key_event_from_linux(type, code, value, out);
        default:
            return -EUNIMPL;
    }
}

#endif
