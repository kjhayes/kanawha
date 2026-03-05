#ifndef __KANAWHA__IDE_IDE_H__
#define __KANAWHA__IDE_IDE_H__

#include <kanawha/dev/blk.h>
#include <kanawha/pio.h>

struct ide_dev;

// Keeps a reference to "name"
int
ide_dev_register(pio_t io_base,
                 pio_t ctrl_base,
                 const char *name,
                 struct ide_dev **out);

int
ide_dev_unregister(struct ide_dev *dev);

#endif
