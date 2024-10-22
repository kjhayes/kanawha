
#include <drivers/pci/pci.h>
#include <kanawha/stddef.h>

#ifdef CONFIG_SYSFS_PCI
#include <drivers/pci/sysfs.h>
#endif

DECLARE_SPINLOCK(pci_match_lock);
DECLARE_ILIST(pci_driver_list);
DECLARE_ILIST(pci_unmatched_func_list);
DECLARE_ILIST(pci_matched_func_list);

static int
pci_try_match(
        struct pci_driver *driver,
        struct pci_func *func)
{
    int res;

    int matched_id = 0;
    for(size_t i = 0; i < driver->num_ids; i++) {
        struct pci_id *id = &driver->ids[i];
        if(id->device == func->device_id &&
           id->vendor == func->vendor_id)
        {
            matched_id = 1;
            break;
        }
    }

    if(!matched_id) {
        return -EINVAL;
    }

    res = pci_driver_probe(driver, func);
    if(res) {
        return res;
    }

    res = pci_driver_init_device(driver, func);
    if(res) {
        return res;
    }

    func->driver = driver;

    return 0;
}

int
register_pci_driver(
        struct pci_driver *driver)
{
    spin_lock(&pci_match_lock);

    ilist_push_tail(&pci_driver_list, &driver->global_node);

    ilist_node_t *node;
    ilist_for_each(node, &pci_unmatched_func_list) {
        struct pci_func *func =
            container_of(node, struct pci_func, global_node);
        int res = pci_try_match(driver, func);
        if(res == 0) {
            ilist_remove(&pci_unmatched_func_list, &func->global_node); 
            ilist_push_tail(&pci_matched_func_list, &func->global_node);
            break;
        }
    }

    spin_unlock(&pci_match_lock);
    return 0;
}

int
register_pci_func(
        struct pci_func *func)
{
    int res;

    spin_lock(&pci_match_lock);

    ilist_push_tail(&pci_unmatched_func_list, &func->global_node);

    ilist_node_t *node;
    ilist_for_each(node, &pci_driver_list) {
        struct pci_driver *driver =
            container_of(node, struct pci_driver, global_node);
        int res = pci_try_match(driver, func);
        if(res == 0) {
            ilist_remove(&pci_unmatched_func_list, &func->global_node); 
            ilist_push_tail(&pci_matched_func_list, &func->global_node);
            break;
        }
    }

#ifdef CONFIG_SYSFS_PCI
    res = pci_sysfs_on_register_pci_func(func);
    if(res) {
        wprintk("Failed to add PCI function to sysfs! (err=%s)\n",
                errnostr(res));
    }
#endif

    spin_unlock(&pci_match_lock);
    return 0;
}

