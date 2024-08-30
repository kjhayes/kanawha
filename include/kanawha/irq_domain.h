#ifndef __KANAWHA__IRQ_DOMAIN_H__
#define __KANAWHA__IRQ_DOMAIN_H__

#include <kanawha/printk.h>
#include <kanawha/list.h>
#include <kanawha/rwlock.h>
#include <kanawha/cpu.h>
#include <kanawha/percpu.h>

struct irq_domain;
struct irq_desc;
struct irq_action;
struct excp_state;

// "Good" Outcomes for an irq_handler_f
// irq_handler_f can also return negative errno's if something is very wrong
//
// irq_handler_f must also be tolerant to being called spurriously (the IRQ line might be shared)

#define IRQ_NONE 0 // We're not certain if this device was the cause of the IRQ or not (keep looking for other actions)
#define IRQ_HANDLED 1 // We did it, and we are certain we caused the IRQ (stop handling other actions)
#define IRQ_UNHANDLED 2 // We are certain this device did not cause the IRQ, (keep looking for other actions)
typedef int(irq_handler_f)(
        struct excp_state *excp_state,
        struct irq_action *action);

typedef struct irq_desc *(irq_resolver_f)(
        struct excp_state *excp_state,
        struct irq_action *action);

#define IRQ_DESC_FLAG_MASKED    (1ULL<<0)
#define IRQ_DESC_FLAG_SPURRIOUS (1ULL<<1)
struct irq_desc
{
    irq_t irq;
    hwirq_t hwirq;

    rlock_t lock;

    unsigned long flags;

    size_t num_actions;
    ilist_t actions;

    struct irq_domain *domain;
    struct irq_dev *dev;
};

/*
 * IRQ Actions
 *
 * IRQ_ACTION_HANDLER:
 *     These are essentially the "leaf" nodes of our graph,
 *     actually doing the work of handling an IRQ for some device.
 *
 * IRQ_ACTION_DIRECT_LINK:
 *     This is a direct link from this IRQ to another IRQ descriptor,
 *     which will have it's actions invoked as well.
 *
 * IRQ_ACTION_PERCPU_LINK:
 *     Same as a DIRECT_LINK except that it contains an array of links
 *     of length CONFIG_MAX_CPUS which is indexed by the current CPU id
 *     when the link is taken.
 *
 * IRQ_ACTION_RESOLVED_LINK:
 *     Uses a "resolver" callback to determine which global IRQ to link to.
 *
 */

struct irq_action
{
    struct irq_desc *desc;
    ilist_node_t list_node;

    enum {
        IRQ_ACTION_HANDLER,
        IRQ_ACTION_DIRECT_LINK,
        IRQ_ACTION_PERCPU_LINK,
        IRQ_ACTION_RESOLVED_LINK,
    } type;

    union {
      struct {
          struct device *device;
          irq_handler_f *handler;
      } handler_data;
      struct {
          struct irq_desc *link;
      } direct_link_data;
      struct {
          struct irq_desc __percpu *link;
      } percpu_link_data;
      struct {
          irq_resolver_f *resolver;
      } resolved_link_data;
    };
};

struct irq_domain *
irq_to_domain(irq_t irq);

irq_t irq_domain_revmap(struct irq_domain *domain, hwirq_t hwirq);

struct irq_desc *
irq_to_desc(irq_t irq);

int mask_irq_desc(struct irq_desc *desc);
int unmask_irq_desc(struct irq_desc *desc);
int trigger_irq_desc(struct irq_desc *desc);

// IRQ Actions
struct irq_action *
irq_install_handler(
        struct irq_desc *desc,
        struct device *device,
        irq_handler_f *handler);

struct irq_action *
irq_install_direct_link(
        struct irq_desc *from,
        struct irq_desc *to);

struct irq_action *
irq_install_percpu_link(struct irq_desc *desc);

int
irq_action_set_percpu_link(
        struct irq_action *action,
        struct irq_desc *percpu_desc,
        cpu_id_t to);

struct irq_action *
irq_install_resolved_link(
        struct irq_desc *desc,
        irq_resolver_f *resolver);
        

// This should "free" the action struct
int
irq_uninstall_action(struct irq_action *action);

int
run_irq_actions(struct irq_desc *desc, struct excp_state *excp_state);

int
handle_irq(struct irq_desc *desc, struct excp_state *excp_state);

// Masking
static inline int
mask_irq(irq_t irq) {
    struct irq_desc *desc = irq_to_desc(irq);
    if(desc == NULL) {
        return -ENXIO;
    }
    return mask_irq_desc(desc);
}

static inline int
unmask_irq(irq_t irq) {
    struct irq_desc *desc = irq_to_desc(irq);
    if(desc == NULL) {
        return -ENXIO;
    }
    return unmask_irq_desc(desc);
}

static inline int
trigger_irq(irq_t irq) {
    struct irq_desc *desc = irq_to_desc(irq);
    if(desc == NULL) {
        return -ENXIO;
    }
    return trigger_irq_desc(desc);
}

// Contiguous range of hwirq
struct irq_domain *
alloc_irq_domain_linear(hwirq_t base_hwirq, size_t num_irqs);
int
free_irq_domain_linear(struct irq_domain *domain);

int
dump_irq_descs(printk_f *printer);

#endif
