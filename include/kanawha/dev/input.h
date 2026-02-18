#ifndef __KANAWHA__INPUT_H__
#define __KANAWHA__INPUT_H__

#include <kanawha/dev.h>
#include <kanawha/bitmap.h>
#include <kanawha/stree.h>
#include <kanawha/waitqueue.h>
#include <kanawha/sysfs/vfs.h>

#include <kanawha/uapi/input.h>

#define INPUT_EVENT_BUFLEN 64
struct input_dev
{
    DECLARE_BITMAP(pressed_bitmap, INPUT_NUM_KEYS);

    size_t buf_head;
    size_t buf_tail;
    struct input_event buffer[INPUT_EVENT_BUFLEN];

    struct waitqueue *read_queue;

    struct dev dev;
};

DECLARE_DEV_TYPE(input_dev);

int
input_driver_enqueue_event(
        struct input_dev *input,
        struct input_event *event);

int
input_driver_dequeue_event(
        struct input_dev *input,
        struct input_event *event);

int
input_driver_event_buffer_empty(
	struct input_dev *input);

int
input_driver_wait_for_event(
	struct input_dev *input);

const char *input_key_to_string(
        input_key_t key);

const char *input_motion_to_string(
        input_motion_t motion);

#endif
