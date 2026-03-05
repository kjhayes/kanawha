#ifndef __KSND_KSND_H__
#define __KSND_KSND_H__

#include <stdint.h>
#include <stddef.h>
#include <kanawha/snd.h>
#include <kanawha/file.h>

struct ksnd_device {
    fd_t stream_file;
};

struct ksnd_device *
ksnd_load_device(
        const char *path);

int
ksnd_unload_device(
        struct ksnd_device *device);

#endif
