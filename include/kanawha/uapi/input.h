#ifndef __KANAWHA__UAPI_INPUT_H__
#define __KANAWHA__UAPI_INPUT_H__

#define INPUT_KEY_XLIST(X)\
X(KEY_A)\
X(KEY_B)\
X(KEY_C)\
X(KEY_D)\
X(KEY_E)\
X(KEY_F)\
X(KEY_G)\
X(KEY_H)\
X(KEY_I)\
X(KEY_J)\
X(KEY_K)\
X(KEY_L)\
X(KEY_M)\
X(KEY_N)\
X(KEY_O)\
X(KEY_P)\
X(KEY_Q)\
X(KEY_R)\
X(KEY_S)\
X(KEY_T)\
X(KEY_U)\
X(KEY_V)\
X(KEY_W)\
X(KEY_X)\
X(KEY_Y)\
X(KEY_Z)\
X(KEY_0)\
X(KEY_1)\
X(KEY_2)\
X(KEY_3)\
X(KEY_4)\
X(KEY_5)\
X(KEY_6)\
X(KEY_7)\
X(KEY_8)\
X(KEY_9)\
X(KEY_ESCAPE)\
X(KEY_TAB)\
X(KEY_BACKTICK)\
X(KEY_SPACE)\
X(KEY_BACKSPACE)\
X(KEY_ENTER)\
X(KEY_LCTRL)\
X(KEY_RCTRL)\
X(KEY_LALT)\
X(KEY_RALT)\
X(KEY_LSHIFT)\
X(KEY_RSHIFT)\
X(KEY_F1)\
X(KEY_F2)\
X(KEY_F3)\
X(KEY_F4)\
X(KEY_F5)\
X(KEY_F6)\
X(KEY_F7)\
X(KEY_F8)\
X(KEY_F9)\
X(KEY_F10)\
X(KEY_F11)\
X(KEY_F12)\
X(KEY_COMMA)\
X(KEY_PERIOD)\
X(KEY_FSLASH)\
X(KEY_BSLASH)\
X(KEY_SEMICOLON)\
X(KEY_MINUS)\
X(KEY_EQUAL_SIGN)\
X(KEY_SINGLE_QUOT)\
X(KEY_OPEN_SQR)\
X(KEY_CLOSE_SQR)\
X(KEY_CAPSLOCK)\
X(KEY_NUMLOCK)\
X(KEY_SCROLLLOCK)\
X(KEY_NUMPAD_0)\
X(KEY_NUMPAD_1)\
X(KEY_NUMPAD_2)\
X(KEY_NUMPAD_3)\
X(KEY_NUMPAD_4)\
X(KEY_NUMPAD_5)\
X(KEY_NUMPAD_6)\
X(KEY_NUMPAD_7)\
X(KEY_NUMPAD_8)\
X(KEY_NUMPAD_9)\
X(KEY_NUMPAD_PERIOD)\
X(KEY_NUMPAD_PLUS)\
X(KEY_NUMPAD_MINUS)\
X(KEY_NUMPAD_ASTERISK)\
X(KEY_UP_ARROW)\
X(KEY_DOWN_ARROW)\
X(KEY_LEFT_ARROW)\
X(KEY_RIGHT_ARROW)\
X(KEY_MOUSE_LEFT)\
X(KEY_MOUSE_RIGHT)\
X(KEY_MOUSE_MIDDLE)\

typedef enum input_key {

    INPUT_KEY_UNKNOWN = 0,

#define DECLARE_KEY_ENUM(__KEY)\
    INPUT_ ## __KEY,
INPUT_KEY_XLIST(DECLARE_KEY_ENUM)
#undef DECLARE_KEY_ENUM

    // Must be last
    INPUT_NUM_KEYS,

} input_key_t;

#define INPUT_MOTION_XLIST(X)\
X(MOTION_RELEASED)\
X(MOTION_PRESSED)\
X(MOTION_HELD)

typedef enum input_motion {

#define DECLARE_MOTION_ENUM(__MOTION)\
    INPUT_ ## __MOTION,
INPUT_MOTION_XLIST(DECLARE_MOTION_ENUM)
#undef DECLARE_MOTION_ENUM

} input_motion_t;

typedef enum {
    INPUT_EVT_KEY,
    INPUT_EVT_MOUSE,
} input_event_type_t;

struct input_event
{
    input_event_type_t type;
    union {
        struct {
            input_key_t key;
            input_motion_t motion;
        };
        struct {
            int mouse_delta_x;
            int mouse_delta_y;
        };
    };
};

#endif
