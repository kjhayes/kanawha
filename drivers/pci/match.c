
#include <drivers/pci/pci.h>
#include <kanawha/stddef.h>

#ifdef CONFIG_SYSFS_PCI
#include <drivers/pci/sysfs.h>
#endif

DECLARE_SPINLOCK(pci_match_lock);
DECLARE_ILIST(pci_driver_list);
DECLARE_ILIST(pci_unmatched_func_list);
DECLARE_ILIST(pci_matched_func_list);

static inline int
pci_id_match(struct pci_func *func, struct pci_id *id)
{
    if(!(id->flags & PCI_ID_IGNORE_VENDOR))
    {
        if(id->vendor != func->vendor_id)
        {
            return 0;
        }
    }

    if(!(id->flags & PCI_ID_IGNORE_DEVICE))
    {
        if(id->device != func->device_id)
        {
            return 0;
        }
    }

    if(id->flags & PCI_ID_CHECK_CLASS)
    {
        if(id->class != func->class_id)
        {
            return 0;
        }
    }

    if(id->flags & PCI_ID_CHECK_SUBCLASS)
    {
        if(id->subclass != func->subclass_id)
        {
            return 0;
        }
    }

    if(id->flags & PCI_ID_CHECK_PROG_IF)
    {
        if(id->prog_if != func->prog_if_id)
        {
            return 0;
        }
    }

    return 1;
}

static int
pci_try_match(struct pci_driver *driver, struct pci_func *func)
{
    int res;

    int matched_id = 0;
    for(size_t i = 0; i < driver->num_ids; i++)
    {
        struct pci_id *id = &driver->ids[i];
        if(pci_id_match(func, id))
        {
            matched_id = 1;
            break;
        }
    }

    if(!matched_id)
    {
        return -EINVAL;
    }

    res = pci_driver_probe(driver, func);
    if(res)
    {
        return res;
    }

    res = pci_driver_init_device(driver, func);
    if(res)
    {
        return res;
    }

    func->driver = driver;
    ilist_push_tail(&driver->devices, &func->driver_node);

    return 0;
}

int
register_pci_driver(struct pci_driver *driver)
{
    int res;

    ilist_init(&driver->devices);

    spin_lock(&pci_match_lock);

    ilist_push_tail(&pci_driver_list, &driver->global_node);

    ilist_node_t *node;
    ilist_for_each(node, &pci_unmatched_func_list)
    {
        struct pci_func *func =
            container_of(node, struct pci_func, global_node);
        res = pci_try_match(driver, func);
        if(res)
        {
            continue;
        }
    }

    ilist_for_each(node, &driver->devices)
    {
        struct pci_func *func =
            container_of(node, struct pci_func, driver_node);
        ilist_remove(&pci_unmatched_func_list, &func->global_node);
        ilist_push_tail(&pci_matched_func_list, &func->global_node);
    }

    spin_unlock(&pci_match_lock);
    return 0;
}

static int
register_pci_func(struct pci_func *func)
{
    int res;

    spin_lock(&pci_match_lock);

    ilist_push_tail(&pci_unmatched_func_list, &func->global_node);

    ilist_node_t *node;
    ilist_for_each(node, &pci_driver_list)
    {
        struct pci_driver *driver =
            container_of(node, struct pci_driver, global_node);
        int res = pci_try_match(driver, func);
        if(res == 0)
        {
            ilist_remove(&pci_unmatched_func_list, &func->global_node);
            ilist_push_tail(&pci_matched_func_list, &func->global_node);
            break;
        }
    }

#ifdef CONFIG_SYSFS_PCI
    res = pci_sysfs_on_register_pci_func(func);
    if(res)
    {
        wprintk("Failed to add PCI function to sysfs! (err=%s)\n",
                errnostr(res));
    }
#endif

    spin_unlock(&pci_match_lock);
    return 0;
}

static int
register_all_pci_funcs(void)
{
    return pci_for_each_func(register_pci_func);
}
declare_init(device, register_all_pci_funcs);

