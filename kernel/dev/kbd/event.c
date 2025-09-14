
#include <kanawha/dev/kbd.h>

const char *
kbd_key_to_string(
    kbd_key_t key)
{
    switch(key) {
#define KBD_KEY_TO_STRING_CASE(__KEY)\
        case KBD_ ## __KEY:\
            return #__KEY;

KBD_KEY_XLIST(KBD_KEY_TO_STRING_CASE)

#undef KBD_KEY_TO_STRING_CASE
        case KBD_KEY_UNKNOWN:
            return "UNKNOWN";
        default:
            return "INVALID-KEY";
    }
}

const char *
kbd_motion_to_string(
    kbd_motion_t motion)
{
    switch(motion) {
#define KBD_MOTION_TO_STRING_CASE(__MOTION)\
        case KBD_ ## __MOTION:\
            return #__MOTION;

KBD_MOTION_XLIST(KBD_MOTION_TO_STRING_CASE)

#undef KBD_MOTION_TO_STRING_CASE
        default:
            return "INVALID-MOTION";
    }
}

