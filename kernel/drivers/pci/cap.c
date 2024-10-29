
#include <drivers/pci/cap.h>
#include <drivers/pci/cfg.h>
#include <drivers/pci/pci.h>
#include <kanawha/kmalloc.h>
#include <kanawha/list.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>

#define PCI_CAP_PTR_OFFSET 0x34

static inline int
pci_cap_ptr_valid(uint8_t ptr)
{
    return ptr >= 0x40;
}

int
pci_func_init_caps(
        struct pci_func *func)
{
    int res;
    uint8_t cap_ptr;

    if(!ilist_empty(&func->cap_list)) {
        return -EINVAL;
    }

    res = pci_func_readb(func, PCI_CAP_PTR_OFFSET, &cap_ptr);
    if(res) {
        eprintk("pci_func_alloc_caps: Failed to read PCI_CAP_PTR field of capability structure! (err=%s)\n",
                errnostr(res));
        return res;
    }
    dprintk("CAP_PTR=0x%x\n", cap_ptr);

    while(pci_cap_ptr_valid(cap_ptr)) {
        struct pci_cap *cap = kmalloc(sizeof(struct pci_cap));
        if(cap == NULL) {
            res = -ENOMEM;
            goto err_exit;
        }
        memset(cap, 0, sizeof(struct pci_cap));

        ilist_push_tail(&func->cap_list, &cap->list_node);

        cap->cfg_offset = cap_ptr;
        res = pci_func_readb(func, cap_ptr, &cap->cap_id);
        if(res) {
            eprintk("pci_func_alloc_caps: Failed to read capability id at offset=0x%lx (err=%s)\n",
                    cap->cfg_offset, errnostr(res));
            goto err_exit;
        }

        res = pci_func_readb(func, cap_ptr+1, &cap_ptr);
        if(res) {
            eprintk("pci_func_alloc_caps: Failed to read next capability pointer at offset=0x%lx (err=%s)\n",
                    cap_ptr+1, errnostr(res));
            goto err_exit;
        }

        dprintk("PCI Capability: func=%p, offset=0x%lx, id=0x%x\n",
                (void*)func, cap->cfg_offset, cap->cap_id);
    }

    return 0;

err_exit:
    while(!ilist_empty(&func->cap_list)) {
        ilist_node_t *node_ptr = ilist_pop_tail(&func->cap_list);
        struct pci_cap *cap =
            container_of(node_ptr, struct pci_cap, list_node);
        kfree(cap);
    }
    return res;
}

int
pci_func_deinit_caps(
        struct pci_func *func)
{
    while(!ilist_empty(&func->cap_list)) {
        ilist_node_t *node_ptr = ilist_pop_tail(&func->cap_list);
        struct pci_cap *cap =
            container_of(node_ptr, struct pci_cap, list_node);
        kfree(cap);
    }
    return 0;
}

struct pci_cap *
pci_func_find_cap(
        struct pci_func *func,
        uint8_t cap_id)
{
    ilist_node_t *cap_node;
    ilist_for_each(cap_node, &func->cap_list)
    {
        struct pci_cap *cap =
            container_of(cap_node, struct pci_cap, list_node);
        if(cap->cap_id == cap_id) {
            return cap;
        }
    }
    return NULL;
}

struct pci_cap *
pci_func_find_next_cap(
        struct pci_func *func,
        struct pci_cap *cap,
        uint8_t cap_id)
{
    cap = container_of(
            cap->list_node.next,
            struct pci_cap,
            list_node);
    while(&cap->list_node != &func->cap_list) {
        cap = container_of(
            cap->list_node.next,
            struct pci_cap,
            list_node);
        if(cap->cap_id == cap_id) {
            return cap;
        }
    }
    return NULL;
}

