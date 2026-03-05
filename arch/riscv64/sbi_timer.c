
#include <kanawha/cpu.h>
#include <kanawha/init.h>
#include <kanawha/irq.h>
#include <kanawha/irq_domain.h>
#include <kanawha/kmalloc.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/timer.h>
#include <kanawha/timer_dev.h>
#include <kanawha/xcall.h>

#include <arch/riscv64/cpu.h>
#include <arch/riscv64/csr.h>
#include <arch/riscv64/hlic.h>
#include <arch/riscv64/sbi.h>

#define SBI_TIMER_EXTID 0x54494D45
#define HLIC_TIMER_HWIRQ 5

struct sbi_timer
{
    struct timer_dev timer_dev;

    irq_t irq;
    struct irq_action *action;

    cpu_id_t cpu_id;

    int periodic;
    duration_t period;

    alarm_f *func;
};

static int
sbi_timer_handler(struct excp_state *excp_state, struct irq_action *action)
{
    int res;
    struct sbi_timer *timer = action->handler_data.priv_data;

    int handled = 0;
    if(timer->func)
    {
        handled = 1;
        (timer->func)();
    }

    // Reset the timer if periodic
    if(timer->periodic)
    {
        freq_t current_timebase = riscv64_cpu_timebase(current_cpu_id());
        cycles_t current_time = riscv64_rdtime();

        cycles_t dur_cycles =
            cycles_from_duration(timer->period, current_timebase);
        cycles_t alarm_time = current_time + dur_cycles;

        struct sbiret ret;
        ret = sbi_ecall(SBI_TIMER_EXTID,
                        0x0, // function id
                        alarm_time,
                        0,
                        0,
                        0,
                        0,
                        0);
        res = sbiret_to_errno(&ret);
        if(res)
        {
            panic("Failed to set SBI periodic timer!\n");
        }

        res = unmask_irq(timer->irq);
        if(res)
        {
            panic("Failed to unmask SBI periodic timer IRQ!\n");
        }
    }
    else
    {
        // Disable the timer if it was a one-shot
        mask_irq(timer->irq);

        // Not strictly necessary
        sbi_ecall(SBI_TIMER_EXTID,
                  0x0, // function id
                  -1ULL,
                  0,
                  0,
                  0,
                  0,
                  0);
    }

    if(handled)
    {
        return IRQ_HANDLED;
    }
    else
    {
        return IRQ_NONE;
    }
}

struct timer_delta
{
    struct sbi_timer *timer;
    duration_t duration;
    alarm_f *func;
    int periodic;
};

static void
sbi_timer_clear_xcall(void *__timer)
{
    struct sbi_timer *timer = __timer;
    mask_irq(timer->irq);

    // Not strictly necessary
    sbi_ecall(SBI_TIMER_EXTID,
              0x0, // function id
              -1ULL,
              0,
              0,
              0,
              0,
              0);
}

static void
sbi_timer_apply_delta_xcall(void *__delta)
{
    int res;

    struct timer_delta *delta = (struct timer_delta *)__delta;
    struct sbi_timer *timer = delta->timer;
    DEBUG_ASSERT(KERNEL_ADDR(timer));

    res = mask_irq(timer->irq);
    if(res)
    {
        eprintk("Failed to mask SBI timer IRQ!\n");
        return;
    }

    if(delta->periodic)
    {
        timer->periodic = 1;
        timer->period = delta->duration;
    }
    else
    {
        timer->periodic = 0;
        timer->period = 0;
    }

    timer->func = delta->func;

    // Actually go ahead and set the timer
    freq_t current_timebase = riscv64_cpu_timebase(current_cpu_id());
    cycles_t current_time = riscv64_rdtime();

    cycles_t dur_cycles =
        cycles_from_duration(delta->duration, current_timebase);
    cycles_t alarm_time = current_time + dur_cycles;

    struct sbiret ret;
    ret = sbi_ecall(SBI_TIMER_EXTID,
                    0x0, // function id
                    alarm_time,
                    0,
                    0,
                    0,
                    0,
                    0);
    res = sbiret_to_errno(&ret);
    if(res)
    {
        eprintk("Failed to set SBI timer!\n");
        return;
    }

    res = unmask_irq(timer->irq);
    if(res)
    {
        eprintk("Failed to unmask SBI timer IRQ!\n");
        return;
    }
}

static int
sbi_timer_clear_alarm(struct timer_dev *dev, size_t alarm)
{
    if(alarm != 0)
    {
        return -ENXIO;
    }

    struct sbi_timer *timer = container_of(dev, struct sbi_timer, timer_dev);

    return xcall_run(timer->cpu_id, sbi_timer_clear_xcall, NULL);
}

static int
sbi_timer_set_alarm_oneshot(struct timer_dev *dev,
                            size_t alarm,
                            duration_t wait_for,
                            alarm_f *func)
{
    if(alarm != 0)
    {
        return -ENXIO;
    }

    struct sbi_timer *timer = container_of(dev, struct sbi_timer, timer_dev);

    struct timer_delta delta = {
        .timer = timer,
        .duration = wait_for,
        .func = func,
        .periodic = 0,
    };

    return xcall_run(timer->cpu_id,
                     sbi_timer_apply_delta_xcall,
                     (void *)&delta);
}

static int
sbi_timer_set_alarm_periodic(struct timer_dev *dev,
                             size_t alarm,
                             duration_t period,
                             alarm_f *func)
{
    if(alarm != 0)
    {
        return -ENXIO;
    }

    struct sbi_timer *timer = container_of(dev, struct sbi_timer, timer_dev);

    struct timer_delta delta = {
        .timer = timer,
        .duration = period,
        .func = func,
        .periodic = 1,
    };

    return xcall_run(timer->cpu_id,
                     sbi_timer_apply_delta_xcall,
                     (void *)&delta);
}

static struct timer_driver sbi_timer_driver = {
    .set_alarm_oneshot = sbi_timer_set_alarm_oneshot,
    .set_alarm_periodic = sbi_timer_set_alarm_periodic,
    .clear_alarm = sbi_timer_clear_alarm,
};

static int
sbi_timer_setup_cpu(cpu_id_t id)
{
    int res;

    hartid_t hartid = cpu_id_to_hartid(id);

    struct sbi_timer *timer = kmalloc(sizeof(struct sbi_timer), KM_KERNEL);
    if(timer == NULL)
    {
        return -ENOMEM;
    }
    memset(timer, 0, sizeof(struct sbi_timer));

    timer->cpu_id = id;
    timer->timer_dev.driver = &sbi_timer_driver;
    timer->timer_dev.alarm_count = 1;

    struct irq_desc *desc = riscv64_hlic_irq_desc(HLIC_TIMER_HWIRQ, id);
    if(desc == NULL)
    {
        kfree(timer);
        return -EINVAL;
    }
    timer->irq = desc->irq;

    timer->action = irq_install_handler(desc, timer, sbi_timer_handler);
    if(timer->action == NULL)
    {
        eprintk("Failed to install SBI timer handler!\n");
        return -EINVAL;
    }

    res = provide_timer(&timer->timer_dev, 0);
    if(res)
    {
        wprintk("Failed to provide timer from SBI timer! (err=%s)\n",
                errnostr(res));
    }

    return 0;
}

static int
sbi_timer_init(void)
{
    int res;

    res = sbi_probe_extension(SBI_TIMER_EXTID);
    if(res)
    {
        return res;
    }

    for(cpu_id_t id = 0; id < total_num_cpus(); id++)
    {
        res = sbi_timer_setup_cpu(id);
        if(res)
        {
            eprintk("Failed to setup SBI timer for CPU (%lu)!\n", (ul_t)id);
            return res;
        }
    }

    return 0;
}
declare_init_desc(post_topo,
                  sbi_timer_init,
                  "Initializing SBI Timer Extension");
