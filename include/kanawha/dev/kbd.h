#ifndef __KANAWHA__KBD_H__
#define __KANAWHA__KBD_H__

#include <kanawha/bitmap.h>
#include <kanawha/stree.h>
#include <kanawha/waitqueue.h>
#include <kanawha/sysfs/vfs.h>
#include <kanawha/registry.h>

#include <kanawha/uapi/kbd.h>

#define KBD_EVENT_BUFLEN 64
struct kbd_dev
{
    DECLARE_BITMAP(pressed_bitmap, KBD_NUM_KEYS);

    size_t buf_head;
    size_t buf_tail;
    struct kbd_event buffer[KBD_EVENT_BUFLEN];

    struct waitqueue *read_queue;

    struct registry_node registry_node;
};

DECLARE_REGISTRY(kbd_dev);

int
kbd_driver_enqueue_event(
        struct kbd_dev *kbd,
        struct kbd_event *event);

int
kbd_driver_dequeue_event(
        struct kbd_dev *kbd,
        struct kbd_event *event);

int
kbd_driver_wait_for_event(
	struct kbd_dev *kbd);

const char *kbd_key_to_string(
        kbd_key_t key);

const char *kbd_motion_to_string(
        kbd_motion_t motion);

#endif
