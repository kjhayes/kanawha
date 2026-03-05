#ifndef __KANAWHA__PCI_MAILBOX_H__
#define __KANAWHA__PCI_MAILBOX_H__

#include <kanawha/irq_domain.h>
#include <kanawha/ops.h>

#define PCI_MAILBOX_MSI_REQ_32_SIG(RET, ARG, ...)                              \
    RET(int)                                                                   \
    ARG(size_t, num_req)                                                       \
    ARG(uint32_t *, addr_out)                                                  \
    ARG(uint16_t *, data_out)

#define PCI_MAILBOX_MSI_REQ_64_SIG(RET, ARG, ...)                              \
    RET(int)                                                                   \
    ARG(size_t, num_req)                                                       \
    ARG(uint64_t *, addr_out)                                                  \
    ARG(uint16_t *, data_out)

#define PCI_MAILBOX_MSIX_REQ_SIG(RET, ARG, ...)                                \
    RET(int)                                                                   \
    ARG(size_t, num_req)                                                       \
    ARG(uint64_t *, addr_out)                                                  \
    ARG(uint32_t *, data_out)

#define PCI_MAILBOX_MSI_GET_DESC_32_SIG(RET, ARG, ...)                         \
    RET(struct irq_desc *)                                                     \
    ARG(uint32_t, addr)                                                        \
    ARG(uint16_t, data)                                                        \
    ARG(size_t, index)

#define PCI_MAILBOX_MSI_GET_DESC_64_SIG(RET, ARG, ...)                         \
    RET(struct irq_desc *)                                                     \
    ARG(uint64_t, addr)                                                        \
    ARG(uint16_t, data)                                                        \
    ARG(size_t, index)

#define PCI_MAILBOX_MSIX_GET_DESC_SIG(RET, ARG, ...)                           \
    RET(struct irq_desc *)                                                     \
    ARG(uint64_t, addr)                                                        \
    ARG(uint32_t, data)                                                        \
    ARG(size_t, index)

#define PCI_MAILBOX_OP_LIST(OP, ...)                                           \
    OP(msi_req_32, PCI_MAILBOX_MSI_REQ_32_SIG, ##__VA_ARGS__)                  \
    OP(msi_req_64, PCI_MAILBOX_MSI_REQ_64_SIG, ##__VA_ARGS__)                  \
    OP(msix_req, PCI_MAILBOX_MSIX_REQ_SIG, ##__VA_ARGS__)                      \
    OP(msi_get_desc_32, PCI_MAILBOX_MSI_GET_DESC_32_SIG, ##__VA_ARGS__)        \
    OP(msi_get_desc_64, PCI_MAILBOX_MSI_GET_DESC_64_SIG, ##__VA_ARGS__)        \
    OP(msix_get_desc, PCI_MAILBOX_MSIX_GET_DESC_SIG, ##__VA_ARGS__)

struct pci_mailbox;

struct pci_mailbox_ops
{
    DECLARE_OP_LIST_PTRS(PCI_MAILBOX_OP_LIST, struct pci_mailbox *);
};

struct pci_mailbox
{
    ilist_node_t list_node;

    struct pci_mailbox_ops *ops;
};

DEFINE_OP_LIST_WRAPPERS(PCI_MAILBOX_OP_LIST,
                        static inline,
                        /* No Prefix */,
                        pci_mailbox,
                        OPS_STRUCT_PTR_ACCESSOR,
                        SELF_ACCESSOR);

#undef PCI_MAILBOX_MSIX_REQ_SIG
#undef PCI_MAILBOX_MSI_REQ_32_SIG
#undef PCI_MAILBOX_MSI_REQ_64_SIG
#undef PCI_MAILBOX_OP_LIST

int
register_pci_mailbox(struct pci_mailbox *mailbox, struct pci_mailbox_ops *ops);

int
unregister_pci_mailbox(struct pci_mailbox *mailbox);

int
pci_mailbox_find_msi32(size_t num_req,
                       uint32_t *addr,
                       uint16_t *data,
                       struct irq_desc *descs[num_req]);
int
pci_mailbox_find_msi64(size_t num_req,
                       uint64_t *addr,
                       uint16_t *data,
                       struct irq_desc *descs[num_req]);
int
pci_mailbox_find_msix(size_t num_req,
                      uint64_t addr[num_req],
                      uint32_t data[num_req],
                      struct irq_desc *descs[num_req]);

#endif
