
#include <drivers/usb/usb.h>
#include <drivers/usb/device.h>
#include <kanawha/list.h>
#include <kanawha/lock.h>

static DECLARE_ILIST(drivers_list);
static DECLARE_ILIST(unmatched_devices_list);
DEFINE_LOCAL_THREAD_LOCK(match_lock);

int
register_usb_device(struct usb_device *device)
{
    match_lock_acquire();
    ilist_push_tail(&unmatched_devices_list, &device->match_node);
    match_lock_release();
    return 0;
}
int
unregister_usb_device(struct usb_device *device)
{
    match_lock_acquire();
    ilist_remove(&unmatched_devices_list, &device->match_node);
    match_lock_release();
    return -EUNIMPL;
}

int
register_usb_driver(struct usb_driver *driver)
{
    match_lock_acquire();
    ilist_push_tail(&drivers_list, &driver->match_node);
    match_lock_release();
    return 0;
}
int
unregister_usb_driver(struct usb_driver *driver)
{
    match_lock_acquire();
    ilist_remove(&drivers_list, &driver->match_node);
    match_lock_release();
    return -EUNIMPL;
}

