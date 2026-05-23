#ifndef __KANAWHA__LENS_INPUT_BUFFER_H__
#define __KANAWHA__LENS_INPUT_BUFFER_H__

#include <kanawha/input.h>
#include <stdlib.h>

struct lens_input_buffer;

struct lens_input_buffer *
lens_create_input_buffer(
        size_t length);
int
lens_destroy_input_buffer(
        struct lens_input_buffer *buffer);

int
lens_input_buffer_push(
        struct lens_input_buffer *buffer,
        struct input_event *evt);

// 0 -> buffer is empty
// 1 -> popped an event
// <0 -> errno
int
lens_input_buffer_pop(
        struct lens_input_buffer *buffer,
        struct input_event *evt);

int
lens_input_buffer_peek(
        struct lens_input_buffer *buffer);

#endif
