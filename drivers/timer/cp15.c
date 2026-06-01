
#include <devtree/devtree.h>
#include <devtree/driver.h>
#include <devtree/flat.h>
#include <devtree/match.h>
#include <devtree/node.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/cpu.h>
#include <kanawha/xcall.h>
#include <kanawha/irq_domain.h>
#include <kanawha/dev/timer.h>

struct cp15_global_timer
{
    irq_t irq;
    struct irq_action *action;

    freq_t global_freq;

    spinlock_t local_timers_lock;
    struct ptree local_timers;
};

#define CP15_TIMER_ONESHOT   (1ULL<<0)
struct cp15_timer {
    cpu_id_t cpu;
    struct timer_dev timer_dev;
    struct ptree_node ptree_node;
    char *name;

    freq_t freq;

    unsigned long flags;
    alarm_f *alarm;
    duration_t period;
};

static inline struct cp15_timer *
cp15_global_timer_create_local(
        struct cp15_global_timer *global,
        cpu_id_t cpu)
{
    struct cp15_timer *timer = kzmalloc(sizeof(*timer), KM_KERNEL);
    if(timer == NULL) {
        return NULL;
    }
    timer->cpu = cpu;
    timer->freq = 0;
    timer->name = NULL;

    spin_lock(&global->local_timers_lock);
    ptree_insert(&global->local_timers, &timer->ptree_node, cpu);
    spin_unlock(&global->local_timers_lock);

    return timer;
}

static inline int
cp15_global_timer_destroy_local(
        struct cp15_global_timer *global,
        struct cp15_timer *local)
{
    spin_lock(&global->local_timers_lock);
    ptree_remove(&global->local_timers, local->ptree_node.key);
    spin_unlock(&global->local_timers_lock);
    kfree(local);
    return 0;
}

static int
cp15_timer_handler(struct excp_state *excp_state, struct irq_action *action)
{
    dprintk("cp15_timer_handler!\n");
    int res;
    struct cp15_global_timer *global = action->handler_data.priv_data;

    struct cp15_timer *timer;
    {
        spin_lock(&global->local_timers_lock);
        struct ptree_node *pnode = ptree_get(&global->local_timers, current_cpu_id());
        spin_unlock(&global->local_timers_lock);
        if(pnode == NULL) {
            wprintk("Could not find local cp15 timer on CPU(%lu)\n",
                    (ul_t)current_cpu_id());
            return IRQ_UNHANDLED;
        }
        timer = container_of(pnode, struct cp15_timer, ptree_node);
    }

    dprintk("cp15_timer handler %p!\n", timer);

    if(!(timer->flags & CP15_TIMER_ONESHOT)) {
        // Reset the timer
        cycles_t cycles = cycles_from_duration(timer->period, timer->freq);
        arm64_sysreg_writeq(CNTP_TVAL_EL0, (uint64_t)cycles);
    }

    alarm_f *alarm = timer->alarm;
    if(alarm != NULL) {
        (*alarm)();
    }

    return IRQ_NONE;
}

static inline void
cp15_disable_alarm_xcall(
        void *_timer)
{
    struct cp15_timer *timer = _timer;
    DEBUG_ASSERT(timer->cpu == current_cpu_id());
    uint64_t ctl = arm64_sysreg_readq(CNTP_CTL_EL0);
    ctl &= ~0b10; // Mask the IRQ and disable the timer 
    arm64_sysreg_writeq(CNTP_CTL_EL0, ctl);
    return;
}
static inline int
cp15_disable_alarm(struct cp15_timer *timer)
{
    return xcall_run(timer->cpu, cp15_disable_alarm_xcall, (void*)timer);
}

static inline void
cp15_start_alarm_xcall(
        void *_timer)
{
    struct cp15_timer *timer = _timer;
    DEBUG_ASSERT(timer->cpu == current_cpu_id());

    // Start off by ensuring the alarm is disabled
    uint64_t ctl = arm64_sysreg_readq(CNTP_CTL_EL0);
    ctl |= 0b10; // Mask the IRQ
    arm64_sysreg_writeq(CNTP_CTL_EL0, ctl);

    // Write the period into TVAL
    cycles_t cycles = cycles_from_duration(timer->period, timer->freq);
    // TODO ensure cycles is 32-bits or fewer
    if((uint64_t)cycles >= (1ULL<<32)) {
        wprintk("CP15: Cannot set timer for cycles=0x%lx! (non-32-bit)\n",
                (ul_t)cycles);
        return;
    }

    arm64_sysreg_writeq(CNTP_TVAL_EL0, (uint64_t)cycles);

    ctl &= ~0b10; // Unmask the IRQ
    ctl |= 1; // Enable the timer
    arm64_sysreg_writeq(CNTP_CTL_EL0, ctl);

    return;
}
static inline int
cp15_start_alarm(struct cp15_timer *timer)
{
    return xcall_run(timer->cpu, cp15_start_alarm_xcall, (void*)timer);
}

static int
cp15_timer_clear_alarm(struct timer_dev *dev, size_t alarm)
{

    int res;
    struct cp15_timer *timer = container_of(dev, struct cp15_timer, timer_dev);
    res = cp15_disable_alarm(timer);
    if(res) {
        return res;
    }
    mbarrier();
    timer->alarm = NULL;
    return 0;
}

static int
cp15_timer_set_alarm_oneshot(struct timer_dev *dev,
                            size_t alarm,
                            duration_t wait_for,
                            alarm_f *func)
{
    int res;
    struct cp15_timer *timer = container_of(dev, struct cp15_timer, timer_dev);
    res = cp15_disable_alarm(timer);
    if(res) {
        return res;
    }

    timer->flags |= CP15_TIMER_ONESHOT;
    timer->period = wait_for;
    timer->alarm = func;

    return cp15_start_alarm(timer);
}

static int
cp15_timer_set_alarm_periodic(struct timer_dev *dev,
                             size_t alarm,
                             duration_t period,
                             alarm_f *func)
{
    int res;
    struct cp15_timer *timer = container_of(dev, struct cp15_timer, timer_dev);
    res = cp15_disable_alarm(timer);
    if(res) {
        return res;
    }

    timer->flags &= ~CP15_TIMER_ONESHOT;
    timer->period = period;
    timer->alarm = func;

    return cp15_start_alarm(timer);
}

static struct timer_driver
cp15_timer_driver = {
    .clear_alarm = cp15_timer_clear_alarm,
    .set_alarm_oneshot = cp15_timer_set_alarm_oneshot,
    .set_alarm_periodic = cp15_timer_set_alarm_periodic,
};

static int
cp15_dt_probe(struct dt_driver *driver, struct dt_node *node)
{
    return 0;
}

static void
cp15_setup_local_cpu_xcall(void *__global)
{
    int res;

    struct cp15_global_timer *global = __global;

    struct cp15_timer *cp15 = cp15_global_timer_create_local(global, current_cpu_id());
    if(cp15 == NULL) {
        wprintk("OOM during CP15 timer dev init on CPU %ld!\n",
                (sl_t)current_cpu_id());
        return;
    }
    cp15->cpu = current_cpu_id();
    {
        char buffer[32];
        snprintk(buffer, 32, "cp15-%ld", (sl_t)cp15->cpu);
        buffer[31] = '\0';
        cp15->name = kstrdup(buffer);
    }
    if(cp15->name == NULL) {
        cp15_global_timer_destroy_local(global, cp15);
        wprintk("OOM during CP15 timer dev init on CPU %ld!\n",
                (sl_t)current_cpu_id());
        return;
    }

    // Get the timer frequency
    if(global->global_freq != 0) {
        cp15->freq = global->global_freq;
    } else {
        cp15->freq = arm64_sysreg_readq(CNTFRQ_EL0);
    }
    printk("CP15 (CPU %ld) has frequency %lu Hz\n",
            (sl_t)cp15->cpu,
            (ul_t)freq_to_hz(cp15->freq));

    cp15->timer_dev.driver = &cp15_timer_driver;
    res = register_timer_dev(&cp15->timer_dev, cp15->name);
    if(res) {
        kfree(cp15->name);
        cp15_global_timer_destroy_local(global, cp15);
        wprintk("Failed to register CP15 timer dev on CPU %ld!\n",
                (sl_t)current_cpu_id());
        return;
    }

    return;
}

static int
cp15_dt_init_node(struct dt_driver *driver, struct dt_node *node)
{
    int res;

    struct cp15_global_timer *timer = kzmalloc(sizeof(*timer), KM_KERNEL);
    if(timer == NULL) {
        return -ENOMEM;
    }
    spinlock_init(&timer->local_timers_lock);
    ptree_init(&timer->local_timers);

    res = dt_node_read_irq(node, 1, &timer->irq);
    if(res) {
        kfree(timer);
        return res;
    }

    uint32_t dt_freq;
    res = dt_node_read_property_u32(node, "clock-frequency", &dt_freq);
    if(res) {
        timer->global_freq = 0;
    } else {
        timer->global_freq = dt_freq;
    }

    res = xcall_broadcast(cp15_setup_local_cpu_xcall, timer);
    if(res) {
        irq_uninstall_action(timer->action);
        kfree(timer);
        return res;
    }

    timer->action = irq_install_handler(
            irq_to_desc(timer->irq),
            (void*)timer,
            cp15_timer_handler);
    if(timer->action == NULL) {
        kfree(timer);
        return -EINVAL;
    }

    unmask_irq(timer->irq);

    return 0;
}
static int
cp15_dt_deinit_node(struct dt_driver *driver, struct dt_node *node)
{
    return -EUNIMPL;
}

static struct dt_driver_ops cp15_dt_driver_ops = {
    .probe = cp15_dt_probe,
    .init_node = cp15_dt_init_node,
    .deinit_node = cp15_dt_deinit_node,
    .xlate_irq = dt_driver_cannot_xlate_irq,
    .xlate_irq_map = dt_driver_cannot_xlate_irq_map,
};

static struct dt_node_id cp15_dt_driver_ids[] = {
    {.compatible = "arm,armv7-timer",},
    {.compatible = "arm,armv8-timer",},
};

static struct dt_driver cp15_dt_driver = {
    .ids = cp15_dt_driver_ids,
    .num_ids = sizeof(cp15_dt_driver_ids) / sizeof(struct dt_node_id),
    .ops = &cp15_dt_driver_ops,
};

static int
register_cp15_dt_driver(void)
{
    int res;
    res = register_dt_driver(&cp15_dt_driver);
    if(res)
    {
        return res;
    }
    return 0;
}
declare_init(late, register_cp15_dt_driver);
