#ifndef __KANAWHA_DRIVERS__PS2_KBD_SCANSET_H__
#define __KANAWHA_DRIVERS__PS2_KBD_SCANSET_H__

#include <kanawha/kbd.h>
#include <drivers/ps2/port.h>

struct ps2_kbd_scanset {
    int(*handle_scancode)(
            uint8_t next_byte,
            unsigned long *scanset_state,
            struct kbd_event *event_out
            );
};

// TODO
//extern struct ps2_kbd_scanset qwerty_scanset_1;

extern struct ps2_kbd_scanset qwerty_scanset_2;

// TODO
//extern struct ps2_kbd_scanset qwerty_scanset_3;

#endif
