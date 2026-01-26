
#include <kanawha/dev/kbd.h>
#include <kanawha/errno.h>
#include <kanawha/spinlock.h>
#include <kanawha/stree.h>
#include <kanawha/stddef.h>
#include <kanawha/init.h>
#include <kanawha/lock.h>
#include <kanawha/kmalloc.h>

static int
kbd_dev_init(
        struct kbd_dev *kbd)
{
    int res;

    for(size_t bit = 0; bit < KBD_NUM_KEYS; bit++) {
        bitmap_clear(kbd->pressed_bitmap, bit);
    }

    kbd->buf_head = 0;
    kbd->buf_tail = 0;

    kbd->read_queue = kmalloc(sizeof(struct waitqueue), KM_KERNEL);
    if(kbd->read_queue == NULL) {
        return -ENOMEM;
    }
    res = waitqueue_init(kbd->read_queue);
    if(res) {
        kfree(kbd->read_queue);
        kbd->read_queue = NULL;
        return res;
    }
    waitqueue_name(kbd->read_queue, kbd_dev_get_name(kbd));

    printk("kbd_dev registered: %s\n", kbd_dev_get_name(kbd));
    return 0;
}

int
kbd_dev_deinit(struct kbd_dev *kbd)
{
    waitqueue_disable(kbd->read_queue);
    wake_all(kbd->read_queue);
    waitqueue_deinit(kbd->read_queue);
    kfree(kbd->read_queue);
    printk("kbd_dev unregistered: %s\n", kbd_dev_get_name(kbd));
    return -EUNIMPL;
}

DEFINE_DEV_TYPE(
	kbd_dev,
	dev,
	kbd_dev_init,
	kbd_dev_deinit);

int
kbd_driver_enqueue_event(
        struct kbd_dev *kbd,
        struct kbd_event *event)
{
    if(((kbd->buf_head+1)%KBD_EVENT_BUFLEN) == kbd->buf_tail) {

        // We filled up the buffer, so we are going to dequeue
        // and lose the oldest key event (updates the bitmap)
        struct kbd_event lost;
        kbd_driver_dequeue_event(kbd, &lost);

        wprintk("kbd(%s) lost key event: (%s, %s)\n",
		kbd_dev_get_name(kbd),
                kbd_key_to_string(lost.key),
                kbd_motion_to_string(lost.motion));
    }

    kbd->buffer[kbd->buf_head] = *event;
    kbd->buf_head = ((kbd->buf_head+1)%KBD_EVENT_BUFLEN);

    if(kbd->read_queue) {
        dprintk("kbd_enqueue: (WAKING ALL)\n");
        wake_all(kbd->read_queue);
    }

    return 0;
}

int
kbd_driver_dequeue_event(
        struct kbd_dev *kbd,
        struct kbd_event *event)
{
    if(kbd->buf_head == kbd->buf_tail) {
        return -EWOULDBLOCK;
    }

    *event = kbd->buffer[kbd->buf_tail];
    kbd->buf_tail = ((kbd->buf_tail+1)%KBD_EVENT_BUFLEN);

    return 0;
}

int
kbd_driver_event_buffer_empty(
	struct kbd_dev *kbd)
{
    return kbd->buf_head == kbd->buf_tail;
}

int
kbd_driver_wait_for_event(
	struct kbd_dev *dev)
{
    wait_on(dev->read_queue);
    return 0;
}

