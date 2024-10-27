
#include <drivers/pci/mailbox.h>
#include <kanawha/list.h>
#include <kanawha/spinlock.h>
#include <kanawha/stddef.h>

static DECLARE_ILIST(pci_mailbox_list);
static DECLARE_SPINLOCK(pci_mailbox_list_lock);

static struct pci_mailbox *
find_and_advance_pci_mailbox(void)
{
    static struct pci_mailbox *current_pci_mailbox = NULL;

    struct pci_mailbox *mb;

    spin_lock(&pci_mailbox_list_lock);

    if(current_pci_mailbox != NULL) {
        mb = current_pci_mailbox; 
    } else if(!ilist_empty(&pci_mailbox_list)) {
        mb = container_of(pci_mailbox_list.next,
                    struct pci_mailbox,
                    list_node);
    } else {
        mb = NULL;
    }

    if(mb) {
        if(mb->list_node.next != &pci_mailbox_list) {
            current_pci_mailbox =
                container_of(mb->list_node.next,
                        struct pci_mailbox,
                        list_node);
        } else {
            current_pci_mailbox = NULL;
        }
    }

    spin_unlock(&pci_mailbox_list_lock);

    return mb;
}

int
register_pci_mailbox(
        struct pci_mailbox *mb,
        struct pci_mailbox_ops *ops)
{
    mb->ops = ops;
    spin_lock(&pci_mailbox_list_lock);
    ilist_push_tail(&pci_mailbox_list, &mb->list_node);
    spin_unlock(&pci_mailbox_list_lock);
    return 0;
}

int
unregister_pci_mailbox(
        struct pci_mailbox *mailbox)
{
    // We just won't allow this for now,
    // removing a PCI mailbox would be very very tricky
    // to say the least if some device is depending on it
    return -EINVAL;
}

static inline int
pci_single_mailbox_find_msi32(
        struct pci_mailbox *mb,
        size_t num_req,
        uint32_t *addr_out,
        uint16_t *data_out,
        struct irq_desc *descs[num_req])
{
    int res;

    uint32_t addr;
    uint16_t data;

    res = pci_mailbox_msi_req_32(
            mb,
            num_req,
            &addr,
            &data);
    if(res) {
        return res;
    }

    for(size_t i = 0; i < num_req; i++) {
        descs[i] = pci_mailbox_msi_get_desc_32(
                mb,
                addr,
                data,
                i);
        if(descs[i] == NULL) {
            return -ENXIO;
        }
    }

    *addr_out = addr;
    *data_out = data;

    return 0;
}

static inline int
pci_single_mailbox_find_msi64(
        struct pci_mailbox *mb,
        size_t num_req,
        uint64_t *addr_out,
        uint16_t *data_out,
        struct irq_desc *descs[num_req])
{
    int res;

    uint64_t addr;
    uint16_t data;

    res = pci_mailbox_msi_req_64(
            mb,
            num_req,
            &addr,
            &data);
    if(res) {
        return res;
    }

    for(size_t i = 0; i < num_req; i++) {
        descs[i] = pci_mailbox_msi_get_desc_64(
                mb,
                addr,
                data,
                i);
        if(descs[i] == NULL) {
            return -ENXIO;
        }
    }

    *addr_out = addr;
    *data_out = data;

    return 0;
}

static inline int
pci_single_mailbox_find_msix(
        struct pci_mailbox *mb,
        size_t num_req,
        uint64_t addr[num_req],
        uint32_t data[num_req],
        struct irq_desc *descs[num_req])
{
    int res;

    for(size_t i = 0; i < num_req; i++) {

        res = pci_mailbox_msix_req(
                mb,
                num_req,
                &addr[i],
                &data[i]);
        if(res) {
            return res;
        }

        descs[i] = pci_mailbox_msix_get_desc(
                mb,
                addr[i],
                data[i],
                i);
        if(descs[i] == NULL) {
            return -ENXIO;
        }
    }

    return 0;
}

int
pci_mailbox_find_msi32(
        size_t num_req,
        uint32_t *addr,
        uint16_t *data,
        struct irq_desc *descs[num_req])
{
    int res;
    struct pci_mailbox *original = find_and_advance_pci_mailbox();
    if(original == NULL) {
        return -ENXIO;
    }

    struct pci_mailbox *iter = original;
    do {
        res = pci_single_mailbox_find_msi32(
                iter,
                num_req,
                addr,
                data,
                descs);
        if(res) {
            iter = find_and_advance_pci_mailbox();
            continue;
        } else {
            return 0;
        }
    } while(iter != original);

    return -ENXIO;

}

int
pci_mailbox_find_msi64(
        size_t num_req,
        uint64_t *addr,
        uint16_t *data,
        struct irq_desc *descs[num_req])
{
    int res;
    struct pci_mailbox *original = find_and_advance_pci_mailbox();
    if(original == NULL) {
        return -ENXIO;
    }

    struct pci_mailbox *iter = original;
    do {
        res = pci_single_mailbox_find_msi64(
                iter,
                num_req,
                addr,
                data,
                descs);
        if(res) {
            iter = find_and_advance_pci_mailbox();
            continue;
        } else {
            return 0;
        }
    } while(iter != original);

    return -ENXIO;
}

int
pci_mailbox_find_msix(
        size_t num_req,
        uint64_t addr[num_req],
        uint32_t data[num_req],
        struct irq_desc *descs[num_req])
{
    int res;
    struct pci_mailbox *original = find_and_advance_pci_mailbox();
    if(original == NULL) {
        return -ENXIO;
    }

    struct pci_mailbox *iter = original;
    do {
        res = pci_single_mailbox_find_msix(
                iter,
                num_req,
                addr,
                data,
                descs);
        if(res) {
            iter = find_and_advance_pci_mailbox();
            continue;
        } else {
            return 0;
        }
    } while(iter != original);

    return -ENXIO;
}

