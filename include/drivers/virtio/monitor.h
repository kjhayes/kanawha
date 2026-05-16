#ifndef __KANAWHA__VIRTIO_MONITOR_H__
#define __KANAWHA__VIRTIO_MONITOR_H__

#include <kanawha/types.h>
#include <drivers/virtio/virtio.h>
#include <drivers/virtio/queue.h>

struct virtio_monitor;

struct virtio_monitor *
virtio_monitor_create(
        struct virtio_queue *queue,
        size_t max_reqs,
        size_t buflen,
        int(*callback)(void *buffer, size_t buflen, void *state),
        void *state);

int
virtio_monitor_destroy(
        struct virtio_monitor *monitor);

int
virtio_monitor_start(
        struct virtio_monitor *monitor);
int
virtio_monitor_stop(
        struct virtio_monitor *monitor);

#endif
