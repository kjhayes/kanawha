#include <kanawha/irq_domain.h>
#include <kanawha/irq.h>
#include <kanawha/ptree.h>
#include <kanawha/printk.h>
#include <kanawha/kmalloc.h>
#include <kanawha/errno.h>
#include <kanawha/string.h>
#include <kanawha/stddef.h>
#include <kanawha/export.h>
#include <kanawha/irq_dev.h>
#include <kanawha/list.h>
#include <kanawha/stddef.h>
#include <kanawha/device.h>
#include <kanawha/percpu.h>
#include <kanawha/assert.h>

static DECLARE_RLOCK(irq_domain_map_lock);
static DECLARE_PTREE(irq_domain_map);
static irq_t __next_irq_to_give = 0;

struct irq_domain
{
    irq_t base_irq;
    size_t num_irq;

    struct irq_desc *irq_descs;
    struct ptree_node tree_node;

    irq_t(*revmap)(struct irq_domain *domain, hwirq_t hwirq);
};

struct irq_domain *
irq_to_domain(irq_t irq)
{
    rlock_read_lock(&irq_domain_map_lock);
    struct ptree_node *node = ptree_get_max_less_or_eq(&irq_domain_map, (uintptr_t)irq);
    rlock_read_unlock(&irq_domain_map_lock);
    if(node == NULL) {
        return NULL;
    }
    struct irq_domain *domain =
        container_of(node, struct irq_domain, tree_node);
    return domain;
}

struct irq_desc *
irq_to_desc(irq_t irq)
{
    struct irq_domain *domain = irq_to_domain(irq);
    if(domain == NULL) {
        return NULL;
    }
    size_t index = irq - domain->base_irq;
    struct irq_desc *desc = &domain->irq_descs[index];

    DEBUG_ASSERT_MSG(
            desc->irq == irq,
            "irq_to_desc(0x%lx) returned irq_desc->irq == 0x%lx", irq, desc->irq);

    return desc;
}

struct irq_action *
irq_install_handler(
        struct irq_desc *desc,
        struct device *device,
        void *priv_data,
        irq_handler_f *handler)
{
    struct irq_action *action;
    action = kmalloc(sizeof(struct irq_action));
    if(action == NULL) {
        return NULL;
    }
    memset(action, 0, sizeof(struct irq_action));

    action->desc = desc;
    action->type = IRQ_ACTION_HANDLER;
    action->handler_data.priv_data = priv_data;
    action->handler_data.device = device;
    action->handler_data.handler = handler;

    rlock_write_lock(&desc->lock);
    ilist_push_tail(&desc->actions, &action->list_node);
    desc->num_actions++;
    rlock_write_unlock(&desc->lock);

    dprintk("Installed irq handler (0x%lx)\n", (ul_t)desc->irq);
    return action;
}

struct irq_action *
irq_install_direct_link(struct irq_desc *from, struct irq_desc *to)
{
    DEBUG_ASSERT_MSG(from != to, "Trivial IRQ Loop %p == %p", from, to);

    struct irq_action *action;
    action = kmalloc(sizeof(struct irq_action));
    if(action == NULL) {
        return NULL;
    }
    memset(action, 0, sizeof(struct irq_action));

    action->desc = from;
    action->type = IRQ_ACTION_DIRECT_LINK;
    action->direct_link_data.link = to;

    int irq_state = disable_save_irqs();

    rlock_write_lock(&from->lock);
    ilist_push_tail(&from->actions, &action->list_node);
    from->num_actions++;
    rlock_write_unlock(&from->lock);

    spin_lock(&to->direct_links_lock);
    ilist_push_tail(&to->direct_links, &action->direct_link_data.incoming_node);
    spin_unlock(&to->direct_links_lock);

    enable_restore_irqs(irq_state);

    return action;
}

struct irq_action *
irq_install_percpu_link(
        struct irq_desc *desc)
{
    struct irq_action *action;
    action = kmalloc(sizeof(struct irq_action));
    if(action == NULL) {
        return NULL;
    }
    memset(action, 0, sizeof(struct irq_action));

    action->desc = desc;
    action->type = IRQ_ACTION_PERCPU_LINK;
    action->percpu_link_data.link = percpu_calloc(sizeof(struct irq_desc*));

    if(action->percpu_link_data.link == PERCPU_NULL) {
        kfree(action);
        return NULL;
    }

    rlock_write_lock(&desc->lock);
    ilist_push_tail(&desc->actions, &action->list_node);
    desc->num_actions++;
    rlock_write_unlock(&desc->lock);

    return action;
}

int
irq_action_set_percpu_link(
        struct irq_action *action,
        struct irq_desc *percpu_desc,
        cpu_id_t to)
{
    DEBUG_ASSERT_MSG(action->desc != percpu_desc, "Trivial IRQ Loop %p == %p", action->desc, percpu_desc);

    if(action->type != IRQ_ACTION_PERCPU_LINK) {
        return -EINVAL;
    }
    struct irq_desc **slot;
    slot = percpu_ptr_specific(action->percpu_link_data.link, to);
    *slot = percpu_desc;
    return 0;
}

struct irq_action *
irq_install_resolved_link(
        struct irq_desc *desc,
        irq_resolver_f *resolver)
{
    struct irq_action *action;
    action = kmalloc(sizeof(struct irq_action));
    if(action == NULL) {
        return NULL;
    }
    memset(action, 0, sizeof(struct irq_action));

    action->desc = desc;
    action->type = IRQ_ACTION_RESOLVED_LINK;
    action->resolved_link_data.resolver = resolver;

    return action;
}

int
irq_uninstall_action(struct irq_action *action)
{
    int res = 0;
    struct irq_desc *desc = action->desc;
    rlock_write_lock(&desc->lock);
    ilist_remove(&desc->actions, &action->list_node);
    desc->num_actions--;
    rlock_write_unlock(&desc->lock);

    if(action->type == IRQ_ACTION_PERCPU_LINK) {
        percpu_free(action->percpu_link_data.link, sizeof(struct irq_desc*));
    }

    kfree(action);
    return res;
}


int
run_irq_actions(struct irq_desc *desc, struct excp_state *excp_state)
{
    int summary_res = IRQ_UNHANDLED;

    rlock_read_lock(&desc->lock);

    size_t action_num = 0;
    ilist_node_t *node;
    ilist_for_each(node, &desc->actions) {
        struct irq_action *action =
            container_of(node, struct irq_action, list_node);

        int res;
        struct irq_desc *link_desc;

        dprintk("CPU (%ld) run_irq_actions(desc=%p,excp_state=%p) irq=0x%llx action=%lld [%s]\n",
            (sl_t)current_cpu_id(), desc, excp_state, (ull_t)desc->irq, action_num,
            action->type == IRQ_ACTION_HANDLER ? "HANDLER" :
            action->type == IRQ_ACTION_DIRECT_LINK ? "DIRECT-LINK" :
            action->type == IRQ_ACTION_PERCPU_LINK ? "PERCPU-LINK" :
            action->type == IRQ_ACTION_RESOLVED_LINK ? "RESOLVED-LINK" : "UNKNOWN");

        action_num++;

        switch(action->type) {
            case IRQ_ACTION_HANDLER:
                res = (*action->handler_data.handler)(excp_state, action);
                break;
            case IRQ_ACTION_DIRECT_LINK:
                res = handle_irq(action->direct_link_data.link, excp_state);
                break;
            case IRQ_ACTION_PERCPU_LINK:
                link_desc = *(struct irq_desc**)percpu_ptr(action->percpu_link_data.link);
                dprintk("CPU (%ld) &link_desc=%p, link_desc=%p\n",
                        (sl_t)current_cpu_id(),
                        (struct irq_desc**)percpu_ptr(action->percpu_link_data.link),
                        link_desc);
                if(link_desc) {
                    res = handle_irq(link_desc, excp_state);
                } else {
                    res = IRQ_UNHANDLED;
                }
                break;
            case IRQ_ACTION_RESOLVED_LINK:
                link_desc = (action->resolved_link_data.resolver)(excp_state, action);
                if(link_desc) {
                    res = handle_irq(link_desc, excp_state);
                } else {
                    res = IRQ_UNHANDLED;
                }
                break;
        }
        
        if(res < 0) {
            rlock_read_unlock(&desc->lock);
            panic("IRQ Handler for IRQ (%ld) returned \"%s\"!\n",
                    desc->irq, errnostr(res));
        }

        if(res == IRQ_HANDLED) {
            summary_res = IRQ_HANDLED;
            break;
        }
        else if(res == IRQ_NONE && summary_res != IRQ_HANDLED) {
            summary_res = IRQ_NONE;
        }
    }

    rlock_read_unlock(&desc->lock);

    if(summary_res == IRQ_UNHANDLED && (desc->flags & IRQ_DESC_FLAG_SPURRIOUS)) {
        // As long as there were no errors, we always consider potentially
        // spurrious descriptors as "handled"
        summary_res = IRQ_NONE;
    }
    return summary_res;
}

int
handle_irq(struct irq_desc *desc, struct excp_state *excp_state)
{
    if(desc->dev && desc->dev->driver->ack_irq) {
        irq_dev_ack_irq(desc->dev, desc->hwirq);
    }

    int res = run_irq_actions(desc, excp_state);

    if(desc->dev && desc->dev->driver->eoi_irq) {
        irq_dev_eoi_irq(desc->dev, desc->hwirq);
    }
    return res;
}

int
mask_irq_desc_single(struct irq_desc *desc)
{
    int res;
    if(desc->dev != NULL) {
        res = irq_dev_mask_irq(desc->dev, desc->hwirq);
        if(res) {
            return res;
        }
    }
    return 0;
}
int
unmask_irq_desc_single(struct irq_desc *desc)
{
    int res;
    if(desc->dev != NULL) {
        res = irq_dev_unmask_irq(desc->dev, desc->hwirq);
        if(res) {
            return res;
        }
    }
    return 0;
}
int
mask_irq_desc_chain(struct irq_desc *desc)
{
    int res;

    res = mask_irq_desc_single(desc);
    if(res) {
        return res;
    }

    int irq_flags = spin_lock_irq_save(&desc->direct_links_lock);
    ilist_node_t *incoming_node;
    ilist_for_each(incoming_node, &desc->direct_links) {
        struct irq_action *direct_link =
            container_of(incoming_node, struct irq_action, direct_link_data.incoming_node);
        res = mask_irq_desc_chain(direct_link->desc);
        if(res) {
            return res;
            spin_unlock_irq_restore(&desc->direct_links_lock, irq_flags);
        }
    }
    spin_unlock_irq_restore(&desc->direct_links_lock, irq_flags);
    return 0;
}

int
unmask_irq_desc_chain(struct irq_desc *desc)
{
    int res;

    res = unmask_irq_desc_single(desc);
    if(res) {
        return res;
    }

    int irq_flags = spin_lock_irq_save(&desc->direct_links_lock);
    ilist_node_t *incoming_node;
    ilist_for_each(incoming_node, &desc->direct_links) {
        struct irq_action *direct_link =
            container_of(incoming_node, struct irq_action, direct_link_data.incoming_node);
        res = unmask_irq_desc_chain(direct_link->desc);
        if(res) {
            spin_unlock_irq_restore(&desc->direct_links_lock, irq_flags);
            return res;
        }
    }
    spin_unlock_irq_restore(&desc->direct_links_lock, irq_flags);
    return 0;
}

int
trigger_irq_desc(struct irq_desc *desc)
{
    int res;
    if(desc->dev == NULL) {
        return -EINVAL;
    }

    res = irq_dev_trigger_irq(desc->dev, desc->hwirq);
    if(res) {
        return res;
    }
    return 0;
}

// Assumes the domain_map lock is held
static int
alloc_free_irq_region(
        size_t num_irq,
        irq_t *base_out)
{
    // Keep this simple for now, and assume we won't have overflow
    if(IRQ_MAX - __next_irq_to_give < num_irq) {
        panic("find_free_irq_region would overflow! Need to implement better IRQ allocation!\n");
        return -ENOMEM;
    }

    *base_out = __next_irq_to_give;
    __next_irq_to_give += num_irq;

    return 0;
}

struct linear_irq_domain {
    struct irq_domain domain;
    hwirq_t base_hwirq;
};

static irq_t
linear_irq_domain_revmap(
        struct irq_domain *domain,
        hwirq_t hwirq)
{
    struct linear_irq_domain *linear =
        container_of(domain, struct linear_irq_domain, domain);
    size_t index = hwirq - linear->base_hwirq;
    if(index >= domain->num_irq) {
        return NULL_IRQ;
    }
    return domain->base_irq + index;
}

struct irq_domain *
alloc_irq_domain_linear(
        hwirq_t base_hwirq,
        size_t num_irq)
{
    int res;
    struct linear_irq_domain *domain;
    domain = kmalloc(sizeof(struct linear_irq_domain));
    if(domain == NULL) {
        return NULL;
    }
    memset(domain, 0, sizeof(struct irq_domain));

    domain->base_hwirq = base_hwirq;
    domain->domain.revmap = linear_irq_domain_revmap;

    domain->domain.num_irq = num_irq;
    domain->domain.irq_descs = kmalloc(sizeof(struct irq_desc) * num_irq);
    if(domain->domain.irq_descs == NULL) {
        kfree(domain);
        return NULL;
    }
    memset(domain->domain.irq_descs, 0, sizeof(struct irq_desc) * num_irq);

    rlock_write_lock(&irq_domain_map_lock);

    res = alloc_free_irq_region(num_irq, &domain->domain.base_irq);
    if(res) {
        rlock_write_unlock(&irq_domain_map_lock);
        kfree(domain->domain.irq_descs);
        kfree(domain);
        return NULL;
    }

    domain->domain.tree_node.key = (uintptr_t)domain->domain.base_irq;
    ptree_insert(&irq_domain_map, &domain->domain.tree_node, (uintptr_t)domain->domain.base_irq);

    for(size_t i = 0; i < num_irq; i++) {
        struct irq_desc *desc = &domain->domain.irq_descs[i];
        desc->domain = &domain->domain;
        desc->irq = domain->domain.base_irq + i;
        desc->hwirq = domain->base_hwirq + i;
        desc->num_actions = 0;
        rlock_init(&desc->lock);
        spinlock_init(&desc->direct_links_lock);
        ilist_init(&desc->actions);
        ilist_init(&desc->direct_links);
    }

    rlock_write_unlock(&irq_domain_map_lock);
    return &domain->domain;
}

int
free_irq_domain_linear(
        struct irq_domain *domain)
{
    struct linear_irq_domain *linear =
        container_of(domain, struct linear_irq_domain, domain);
    kfree(domain->irq_descs);
    kfree(linear);
    return 0;
}

irq_t irq_domain_revmap(
        struct irq_domain *domain,
        hwirq_t hwirq)
{
    return (*domain->revmap)(domain, hwirq);
}

int
dump_irq_descs(printk_f *printer)
{
    char dev_name_buf[64];
    dev_name_buf[63] = '\0';

    int irq_flags = disable_save_irqs();

    rlock_read_lock(&irq_domain_map_lock);
    struct ptree_node *node;
    node = ptree_get_first(&irq_domain_map);
    while(node != NULL) {

        struct irq_domain *domain =
            container_of(node, struct irq_domain, tree_node);
        (*printer)("Domain: [0x%x - 0x%x] {\n",
                domain->base_irq, (domain->base_irq + domain->num_irq)-1);
        for(size_t index = 0; index < domain->num_irq; index++) {
            irq_t irq = domain->base_irq + index;
            (*printer)("\tIRQ(0x%x) -> ", irq);
            struct irq_desc *desc = &domain->irq_descs[index];
            if(desc == NULL) {
                (*printer)("NULL");
            } else {
                (*printer)("HWIRQ(0x%x)",
                        desc->hwirq);
            }

            if(desc->dev != NULL) {
                device_read_name(desc->dev->device, dev_name_buf, 63);
                (*printer)(" DEVICE(%s)",
                        dev_name_buf);
            }

            (*printer)("\n");

            ilist_node_t *action_node;
            ilist_for_each(action_node, &desc->actions) {
                (*printer)("\t\t");
                struct irq_action *action =
                    container_of(action_node, struct irq_action, list_node);

                switch(action->type) {
                    case IRQ_ACTION_HANDLER:
                        if(action->handler_data.device) {
                            device_read_name(action->handler_data.device, dev_name_buf, 63);
                        } else {
                            strncpy(dev_name_buf, "NULL", 63);
                        }
                        (*printer)("HANDLER(%p) DEVICE(%s)\n",
                                action->handler_data.handler,
                                dev_name_buf);
                        break;
                    case IRQ_ACTION_DIRECT_LINK:
                        (*printer)("DIRECT-LINK(0x%lx)\n",
                                (ul_t)action->direct_link_data.link->irq);
                        break;
                    case IRQ_ACTION_PERCPU_LINK:
                        (*printer)("PERCPU-LINK\n");
                        for(cpu_id_t id = 0; id < total_num_cpus(); id++) {
                            (*printer)("\t\t\tCPU(%d) DESC(%p)\n",
                                    id, percpu_ptr_specific(action->percpu_link_data.link, id));
                        }
                        break;      
                    case IRQ_ACTION_RESOLVED_LINK:
                        (*printer)("RESOLVED-LINK RESOLVER(%p)\n",
                                action->resolved_link_data.resolver);
                        break;
                }
            }

            ilist_node_t *incoming_node;
            ilist_for_each(incoming_node, &desc->direct_links) {
                (*printer)("\t\t");
                struct irq_action *direct_link =
                    container_of(incoming_node, struct irq_action, direct_link_data.incoming_node);
                (*printer)("INCOMING-LINK(0x%lx)\n", (ul_t)direct_link->desc->irq);
            }
        }
        (*printer)("}\n");

        node = ptree_get_next(node);
    }
    rlock_read_unlock(&irq_domain_map_lock);
    enable_restore_irqs(irq_flags);
    return 0;
}

EXPORT_SYMBOL(alloc_irq_domain_linear);
EXPORT_SYMBOL(free_irq_domain_linear);
EXPORT_SYMBOL(irq_to_desc);
EXPORT_SYMBOL(irq_to_domain);

