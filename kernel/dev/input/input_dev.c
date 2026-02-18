
#include <kanawha/dev/input.h>
#include <kanawha/errno.h>
#include <kanawha/spinlock.h>
#include <kanawha/stree.h>
#include <kanawha/stddef.h>
#include <kanawha/init.h>
#include <kanawha/lock.h>
#include <kanawha/kmalloc.h>

static int
input_dev_init(
        struct input_dev *input)
{
    int res;

    for(size_t bit = 0; bit < INPUT_NUM_KEYS; bit++) {
        bitmap_clear(input->pressed_bitmap, bit);
    }

    input->buf_head = 0;
    input->buf_tail = 0;

    input->read_queue = kmalloc(sizeof(struct waitqueue), KM_KERNEL);
    if(input->read_queue == NULL) {
        return -ENOMEM;
    }
    res = waitqueue_init(input->read_queue);
    if(res) {
        kfree(input->read_queue);
        input->read_queue = NULL;
        return res;
    }
    waitqueue_name(input->read_queue, input_dev_get_name(input));

    printk("input_dev registered: %s\n", input_dev_get_name(input));
    return 0;
}

int
input_dev_deinit(struct input_dev *input)
{
    waitqueue_disable(input->read_queue);
    wake_all(input->read_queue);
    waitqueue_deinit(input->read_queue);
    kfree(input->read_queue);
    printk("input_dev unregistered: %s\n", input_dev_get_name(input));
    return -EUNIMPL;
}

DEFINE_DEV_TYPE(
	input_dev,
	dev,
	input_dev_init,
	input_dev_deinit);

int
input_driver_enqueue_event(
        struct input_dev *input,
        struct input_event *event)
{
    if(((input->buf_head+1)%INPUT_EVENT_BUFLEN) == input->buf_tail) {

        // We filled up the buffer, so we are going to dequeue
        // and lose the oldest key event (updates the bitmap)
        struct input_event lost = { 0 };
        input_driver_dequeue_event(input, &lost);

        wprintk("input(%s) lost key event: (%s, %s)\n",
                input_dev_get_name(input),
                input_key_to_string(lost.key),
                input_motion_to_string(lost.motion));
    }

    input->buffer[input->buf_head] = *event;
    input->buf_head = ((input->buf_head+1)%INPUT_EVENT_BUFLEN);

    if(input->read_queue) {
        dprintk("input_enqueue: (WAKING ALL)\n");
        wake_all(input->read_queue);
    }

    return 0;
}

int
input_driver_dequeue_event(
        struct input_dev *input,
        struct input_event *event)
{
    if(input->buf_head == input->buf_tail) {
        return -EWOULDBLOCK;
    }

    *event = input->buffer[input->buf_tail];
    input->buf_tail = ((input->buf_tail+1)%INPUT_EVENT_BUFLEN);

    return 0;
}

int
input_driver_event_buffer_empty(
	struct input_dev *input)
{
    return input->buf_head == input->buf_tail;
}

int
input_driver_wait_for_event(
	struct input_dev *dev)
{
    wait_on(dev->read_queue);
    return 0;
}

