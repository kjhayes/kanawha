#ifndef __KANAWHA__VIRTIO_VIRTIO_H__
#define __KANAWHA__VIRTIO_VIRTIO_H__

#include <drivers/virtio/device.h>

#define VIRTIO_STATUS_ACKNOWLEDGE        (1ULL<<0)
#define VIRTIO_STATUS_DRIVER             (1ULL<<1)
#define VIRTIO_STATUS_DRIVER_OK          (1ULL<<2)
#define VIRTIO_STATUS_FEATURES_OK        (1ULL<<3)
#define VIRTIO_STATUS_DEVICE_NEEDS_RESET (1ULL<<6)
#define VIRTIO_STATUS_FAILED             (1ULL<<7)

#define VIRTIO_F_NOTIFICATION_DATA (38)

#endif
