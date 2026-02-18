
#include <kanawha/dev/input.h>

const char *
input_key_to_string(
    input_key_t key)
{
    switch(key) {
#define INPUT_KEY_TO_STRING_CASE(__KEY)\
        case INPUT_ ## __KEY:\
            return #__KEY;

INPUT_KEY_XLIST(INPUT_KEY_TO_STRING_CASE)

#undef INPUT_KEY_TO_STRING_CASE
        case INPUT_KEY_UNKNOWN:
            return "UNKNOWN";
        default:
            return "INVALID-KEY";
    }
}

const char *
input_motion_to_string(
    input_motion_t motion)
{
    switch(motion) {
#define INPUT_MOTION_TO_STRING_CASE(__MOTION)\
        case INPUT_ ## __MOTION:\
            return #__MOTION;

INPUT_MOTION_XLIST(INPUT_MOTION_TO_STRING_CASE)

#undef INPUT_MOTION_TO_STRING_CASE
        default:
            return "INVALID-MOTION";
    }
}

