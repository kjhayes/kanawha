
#include <kanawha/stddef.h>
#include <kanawha/stdint.h>
#include <kanawha/printk.h>
#include <arch/x64/lapic.h>
#include <arch/x64/cpu.h>
#include <kanawha/timer_dev.h>
#include <kanawha/init.h>
#include <kanawha/irq_domain.h>
#include <kanawha/cpu.h>
#include <kanawha/clk.h>
#include <kanawha/timer.h>
#include <kanawha/xcall.h>

#define APIC_TIMER_MIN_NUM_CALIBRATIONS 8
#define APIC_TIMER_MAX_NUM_CALIBRATION_ATTEMPTS 12
#define APIC_CALIBRATION_SPIN_MULTIPLIER 2000000

static int
apic_timer_handler(struct excp_state *excp_state, struct irq_action *action)
{
    struct device *dev = action->handler_data.device;
    struct lapic_timer *apic_timer =
        container_of(dev, struct lapic_timer, device);

    if(apic_timer->alarm_func) {
        alarm_f *func = apic_timer->alarm_func;
        dprintk("APIC Timer Running %p\n", func);
        if(!apic_timer->periodic) {
            apic_timer->alarm_func = NULL;
        }
        (*func)();
    } else {
        dprintk("APIC Timer without callback!\n");
    }

    return IRQ_NONE; // Could be someone else
}

static void
lapic_timer_set_mode_oneshot(struct lapic *apic) {
    uint32_t timer_lvt = lapic_read_reg(apic, LAPIC_REG_LVT_TIMER);
    timer_lvt &= ~(1ULL<<17);
    lapic_write_reg(apic, LAPIC_REG_LVT_TIMER, timer_lvt);
}

static void
lapic_timer_set_mode_periodic(struct lapic *apic) {
    uint32_t timer_lvt = lapic_read_reg(apic, LAPIC_REG_LVT_TIMER);
    timer_lvt |= 1ULL<<17;
    lapic_write_reg(apic, LAPIC_REG_LVT_TIMER, timer_lvt);
}

int
apic_timer_init_current(void)
{
    int res;

    dprintk("Initializing APIC Timer on CPU %ld\n", (long)current_cpu_id());
    if(clk_source_get() == NULL) {
        eprintk("Cannot calibrate APIC timer without a clock-source!\n");
        return -ENODEV;
    }

    struct cpu *gen_cpu = cpu_from_id(current_cpu_id());
    struct x64_cpu *cpu = container_of(gen_cpu, struct x64_cpu, cpu);

    struct lapic *apic = &cpu->apic;
    struct lapic_timer *apic_timer = &cpu->apic_timer;

    irq_t timer_irq = irq_domain_revmap(apic->lvt_domain, LAPIC_LVT_TIMER_HWIRQ);
    if(timer_irq == NULL_IRQ) {
        eprintk("Failed to get local APIC Timer IRQ\n");
        return -ENXIO;
    }
    res = mask_irq(timer_irq);
    if(res) {
        eprintk("Failed to mask APIC Timer IRQ before calibration!\n");
        return res;
    }

    struct irq_action *timer_action =
        irq_install_handler(
            irq_to_desc(timer_irq),
            &cpu->apic_timer.device,
            apic_timer_handler);

    if(timer_action == NULL) {
        eprintk("Failed to add handler to APIC Timer interrupt!\n");
        return -EINVAL;
    }

    // Set the DCR
    lapic_write_reg(apic, LAPIC_REG_TMR_DCR, 0b1011); // Divide by 1

    lapic_timer_set_mode_oneshot(apic);

    freq_t calibrated_freq;
    freq_t measured_freq[APIC_TIMER_MAX_NUM_CALIBRATION_ATTEMPTS];

    size_t num_successful_trials = 0;
    size_t num_trials = 0;

    // Unmask the IRQ
    res = unmask_irq(timer_irq);
    if(res) {
        eprintk("Failed to unmask APIC Timer IRQ before calibration!\n");
        irq_uninstall_action(timer_action);
        return res;
    }

    for(size_t trial = 0; trial < APIC_TIMER_MAX_NUM_CALIBRATION_ATTEMPTS; trial++)
    {
        lapic_write_reg(apic, LAPIC_REG_TMR_ICR, 0xFFFFFFFF);

        duration_t mono_base = clk_mono_current();
        cycles_t cycles_base = lapic_read_reg(apic, LAPIC_REG_TMR_CCR);

        // Spin so we don't have too few cycles
        for(volatile size_t spin_cntr = 0; spin_cntr < APIC_CALIBRATION_SPIN_MULTIPLIER * (trial+1); spin_cntr++) {}

        duration_t mono_end = clk_mono_current();
        cycles_t cycles_end = lapic_read_reg(apic, LAPIC_REG_TMR_CCR);

        if(mono_base >= mono_end) {
            eprintk("Failed APIC Calibration Attempt (Clock Error) clk-base = 0x%llx, clock-end = 0x%llx (trial = %d)\n",
                    (unsigned long long)mono_base, (unsigned long long)mono_end, (int)trial);
            continue;
        }

        if(cycles_base <= cycles_end || (cycles_end == 0)) {
            eprintk("Failed APIC Calibration Attempt (Timer Error) cycles-base = 0x%llx, cycles-end = 0x%llx (trial = %d)\n",
                    (unsigned long long)cycles_base, (unsigned long long)cycles_end, (int)trial);
            continue;
        }

        duration_t elapsed_time = mono_end - mono_base; // Counting Up
        cycles_t elapsed_cycles = cycles_base - cycles_end; // Counting Down

        freq_t freq = timed_cycles_to_freq(elapsed_time, elapsed_cycles);

        measured_freq[num_successful_trials] = freq;
        num_successful_trials++;

        if(num_successful_trials >= APIC_TIMER_MIN_NUM_CALIBRATIONS) {
            break;
        }
    }

    // TODO: A Less Overflow Prone Averaging
    freq_t avg = 0;
    for(size_t i = 0; i < num_successful_trials; i++) {
        avg += measured_freq[i];
        dprintk("Trial(%d) : %llu Mhz\n",
                (int)i, (unsigned long long)freq_to_mhz(measured_freq[i]));
    }
    calibrated_freq = avg / num_successful_trials;

    if(num_successful_trials < APIC_TIMER_MIN_NUM_CALIBRATIONS) {
        eprintk("Failed to calibrate the APIC timer!\n");
        irq_uninstall_action(timer_action);
        return -EIMPREC;
    }

    apic_timer->freq = calibrated_freq;

    res = mask_irq(timer_irq);
    if(res) {
        wprintk("Failed to re-mask APIC Timer IRQ after calibration!\n");
    }

    dprintk("Calibrated APIC Timer Frequency (%llu Mhz)\n",
            (unsigned long long)freq_to_mhz(calibrated_freq));

    return 0;
}

static int
lapic_timer_device_read_name(
        struct device *device,
        char *buf,
        size_t buf_size)
{
    struct lapic_timer *timer =
        container_of(device, struct lapic_timer, device);
    struct x64_cpu *cpu =
        container_of(timer, struct x64_cpu, apic_timer);
    
    snprintk(buf, buf_size, "apic-timer-%ld", cpu->apic.id);

    return 0;
}

static struct device_ops
lapic_timer_device_ops = {
    .read_name = lapic_timer_device_read_name,
};

static void
lapic_timer_clear_xcall(void *state)
{
    struct cpu *gen_cpu = cpu_from_id(current_cpu_id());
    struct x64_cpu *cpu = container_of(gen_cpu, struct x64_cpu, cpu);

    irq_t timer_irq = irq_domain_revmap(cpu->apic.lvt_domain, LAPIC_LVT_TIMER_HWIRQ);
    mask_irq(timer_irq);

    return;
}

static int
lapic_timer_clear_alarm(
        struct timer_dev *timer_dev,
        size_t alarm)
{
    if(alarm != 0) {
        return -ENXIO;
    }

    struct lapic_timer *lapic_timer =
        container_of(timer_dev, struct lapic_timer, timer_dev);
    struct x64_cpu *cpu =
        container_of(lapic_timer, struct x64_cpu, apic_timer);

    return xcall_run(cpu->cpu.id, lapic_timer_clear_xcall, NULL);
}

static inline void
lapic_local_timer_set_for_duration(
        struct lapic *lapic,
        struct lapic_timer *timer,
        duration_t duration)
{
    // We assume the DCR is set to divide by 1 still
    cycles_t cycles = cycles_from_duration(duration, timer->freq);
    dprintk("CPU (%ld) lapic_local_timer_set_for_duration(duration = %ld ms, cycles = 0x%llx)\n",
            (sl_t)current_cpu_id(),
            (sl_t)duration_to_msec(duration),
            cycles);
    lapic_write_reg(lapic, LAPIC_REG_TMR_ICR, (uint32_t)cycles);
}

static void
lapic_timer_set_oneshot_xcall(void *__duration)
{
    duration_t duration = (duration_t)(uintptr_t)(__duration);

    struct cpu *gen_cpu = cpu_from_id(current_cpu_id());
    struct x64_cpu *cpu = container_of(gen_cpu, struct x64_cpu, cpu);

    struct lapic *lapic = &cpu->apic;
    struct lapic_timer *timer = &cpu->apic_timer;

    irq_t timer_irq = irq_domain_revmap(lapic->lvt_domain, LAPIC_LVT_TIMER_HWIRQ);
    
    mask_irq(timer_irq);

    lapic_timer_set_mode_oneshot(lapic);
    lapic_local_timer_set_for_duration(lapic, timer, duration);

    unmask_irq(timer_irq);

    return;
}

static void
lapic_timer_set_periodic_xcall(void *__duration)
{
    duration_t duration = (duration_t)(uintptr_t)(__duration);
    uint32_t icr_value;

    struct cpu *gen_cpu = cpu_from_id(current_cpu_id());
    struct x64_cpu *cpu = container_of(gen_cpu, struct x64_cpu, cpu);

    struct lapic *lapic = &cpu->apic;
    struct lapic_timer *timer = &cpu->apic_timer;

    irq_t timer_irq = irq_domain_revmap(lapic->lvt_domain, LAPIC_LVT_TIMER_HWIRQ);

    mask_irq(timer_irq);

    lapic_timer_set_mode_periodic(lapic);
    lapic_local_timer_set_for_duration(lapic, timer, duration);

    unmask_irq(timer_irq);

    return;
}

static int
lapic_timer_set_alarm_oneshot(
        struct timer_dev *timer_dev,
        size_t alarm,
        duration_t wait_for,
        alarm_f *func)
{
    if(alarm != 0) {
        return -ENXIO;
    }

    struct lapic_timer *lapic_timer =
        container_of(timer_dev, struct lapic_timer, timer_dev);

    lapic_timer->alarm_func = func;
    lapic_timer->periodic = 0;

    struct x64_cpu *cpu =
        container_of(lapic_timer, struct x64_cpu, apic_timer);

    return xcall_run(cpu->cpu.id, lapic_timer_set_oneshot_xcall, (void*)(uintptr_t)wait_for);
}

static int
lapic_timer_set_alarm_periodic(
        struct timer_dev *timer_dev,
        size_t alarm,
        duration_t period,
        alarm_f *func)
{
    if(alarm != 0) {
        return -ENXIO;
    }

    struct lapic_timer *lapic_timer =
        container_of(timer_dev, struct lapic_timer, timer_dev);

    lapic_timer->alarm_func = func;
    lapic_timer->periodic = 1;

    struct x64_cpu *cpu =
        container_of(lapic_timer, struct x64_cpu, apic_timer);

    return xcall_run(cpu->cpu.id, lapic_timer_set_periodic_xcall, (void*)(uintptr_t)period);
}

static struct timer_driver
lapic_timer_driver = {
    .clear_alarm = lapic_timer_clear_alarm,
    .set_alarm_oneshot = lapic_timer_set_alarm_oneshot,
    .set_alarm_periodic = lapic_timer_set_alarm_periodic,
};

int
register_cpu_lapic_timer(
        struct x64_cpu *cpu)
{
    int res;

    struct lapic_timer *timer = &cpu->apic_timer;

    res = register_device(
            &timer->device,
            &lapic_timer_device_ops,
            &cpu->cpu.device);

    timer->timer_dev.device = &timer->device;
    timer->timer_dev.driver = &lapic_timer_driver;
    timer->timer_dev.alarm_count = 1;
    timer->alarm_func = NULL;
    timer->periodic = 0;

    if(cpu->cpu.is_bsp) {
        printk("Setting BSP APIC Timer as Timer Source\n");
        res = timer_source_set(&timer->timer_dev, 0);
        if(res) {
            eprintk("Failed to set BSP APIC Timer as timer source! (err=%s)\n",
                    errnostr(res));
        }
    }

    return res;
}

