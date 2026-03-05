
#include <ksnd/ksnd.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/file.h>
#include <kanawha/snd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

struct ksnd_device *
ksnd_load_device(
        const char *path)
{
    struct ksnd_device *dev;
    dev = malloc(sizeof(*dev));
    if(dev == NULL) {
        return NULL;
    }
    return dev;
}

int
ksnd_unload_device(
        struct ksnd_device *dev)
{
    free(dev);
    return 0;
}

