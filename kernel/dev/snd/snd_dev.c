
#include <kanawha/dev/snd.h>
#include <kanawha/init.h>

static int
snd_dev_init(struct snd_dev *dev)
{
    printk("snd_dev registered: %s\n", snd_dev_get_name(dev));
    return 0;
}

static int
snd_dev_deinit(struct snd_dev *dev)
{
    printk("snd_dev unregistered: %s\n", snd_dev_get_name(dev));
    return 0;
}

DEFINE_DEV_TYPE(
        snd_dev,
        dev,
        snd_dev_init,
        snd_dev_deinit
        );

#ifdef CONFIG_LOG_SNDDEV_REGISTRY_ON_LAUNCH
static int
dump_snd_dev_on_launch(void) {
    return dump_snd_dev_registry(do_printk);
}
declare_init(launch, dump_snd_dev_on_launch);
#endif


