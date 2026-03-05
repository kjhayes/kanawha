
#include <drivers/blk/ide/ide.h>
#include <kanawha/errno.h>
#include <kanawha/init.h>
#include <kanawha/printk.h>

static struct ide_dev *legacy_ide_0 = NULL;
static struct ide_dev *legacy_ide_1 = NULL;

static int
ide_probe_legacy(void)
{
    int res;
    res = ide_dev_register(0x1F0, 0x3F6, "ide-0", &legacy_ide_0);
    if(res)
    {
        legacy_ide_0 = NULL;
        wprintk("Failed to register legacy IDE controller 0! (err=%s)\n",
                errnostr(res));
        return 0;
    }
    res = ide_dev_register(0x170, 0x376, "ide-1", &legacy_ide_1);
    if(res)
    {
        legacy_ide_1 = NULL;
        wprintk("Failed to register legacy IDE controller 1! (err=%s)\n",
                errnostr(res));
        return 0;
    }
    return 0;
}

declare_init_desc(device, ide_probe_legacy, "Probing Legacy IDE Device");
