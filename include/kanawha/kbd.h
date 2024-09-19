#ifndef __KANAWHA__KBD_H__
#define __KANAWHA__KBD_H__

#include <kanawha/bitmap.h>
#include <kanawha/stree.h>
#include <kanawha/fs/flat.h>

#include <kanawha/uapi/kbd.h>

#define KBD_EVENT_BUFLEN 64
struct kbd
{
    struct stree_node global_node;
    struct flat_node flat_fs_node;

    DECLARE_BITMAP(pressed_bitmap, KBD_NUM_KEYS);
    size_t buf_head;
    size_t buf_tail;
    struct kbd_event buffer[KBD_EVENT_BUFLEN];
};

// Initialize the internal buffer of the kbd,
// in-case events occur before the keyboard
// can safely be fully registered
int
kbd_init_struct(
        struct kbd *kbd);

// Keeps a reference to "name"
int
register_kbd(
        struct kbd *kbd,
        const char *name);

int
unregister_kbd(
        struct kbd *kbd);

int
kbd_enqueue_event(
        struct kbd *kbd,
        struct kbd_event *event);

int
kbd_dequeue_event(
        struct kbd *kbd,
        struct kbd_event *event);

const char *kbd_key_to_string(
        kbd_key_t key);

const char *kbd_motion_to_string(
        kbd_motion_t motion);

#endif
