
#include <kanawha/stddef.h>
#include <kanawha/types.h>
#include <kanawha/printk.h>
#include <kanawha/init.h>
#include <stdint.h>
#include <kanawha/irq_domain.h>
#include <kanawha/cpu.h>
#include <kanawha/clk.h>
#include <kanawha/pio.h>
#include <kanawha/dev/clk.h>

const static pio_t DEFAULT_CHANNEL_0 = 0x40;
const static pio_t DEFAULT_CHANNEL_1 = 0x41;
const static pio_t DEFAULT_CHANNEL_2 = 0x42;
const static pio_t DEFAULT_MODE_COMMAND = 0x43;

#define PIT_HZ ((hz_t)1193182)

static struct pit_dev {
    struct clk_dev clk_dev;
    irq_lock_t lock;
    pio_t channel[3];
    pio_t mode_command;
} pit_dev;

static freq_t
pit_clk_freq(struct clk_dev *clk_dev)
{
    return hz_to_freq(PIT_HZ);
}

static cycles_t
pit_clk_mono_cycles(struct clk_dev *clk_dev)
{
    // Read from channel 1
    struct pit_dev *dev = container_of(clk_dev, struct pit_dev, clk_dev);
    irq_lock_acquire(&dev->lock);
    uint16_t value;
    value = inb(dev->channel[1]);
    value |= ((uint16_t)inb(dev->channel[1]))<<8;
    irq_lock_release(&dev->lock);
    cycles_t cycles = (cycles_t)(0xFFFF-value);
    printk("PIT cycles = 0x%lx\n",
            (ul_t)cycles);
    return cycles;
}

static struct clk_driver
pit_clk_driver = {
    .freq = pit_clk_freq,
    .mono_cycles = pit_clk_mono_cycles,
};

static void
connect_pc_speaker_to_pit(void)
{
    uint8_t cur = inb(0x61);
    cur |= 0b11;
    outb(0x61, cur);
}

__maybe_unused
static void
disconnect_pc_speaker_from_pit(void)
{
    uint8_t cur = inb(0x61);
    cur &= ~0b11;
    outb(0x61, cur);
}

static int
pc_speaker_set_tone(
        struct pit_dev *pit,
        freq_t freq)
{
    if(freq == 0) {
        disconnect_pc_speaker_from_pit();
        return 0;
    }

    freq_t pit_freq = hz_to_freq(PIT_HZ);
    if(freq > pit_freq) {
        return -EINVAL;
    }
    uint16_t div = pit_freq / freq;
    outb(pit->mode_command, 0b10110110);
    outb(pit->channel[2], div & 0xFF);
    outb(pit->channel[2], (div >> 8) & 0xFF);

    connect_pc_speaker_to_pit();

    return 0;
}

static int
pit_init(void)
{
    int res;

    struct pit_dev *pit = &pit_dev;

    pit->clk_dev.driver = &pit_clk_driver;

    irq_lock_init(&pit->lock);
    pit->channel[0] = DEFAULT_CHANNEL_0;
    pit->channel[1] = DEFAULT_CHANNEL_1;
    pit->channel[2] = DEFAULT_CHANNEL_2;
    pit->mode_command = DEFAULT_MODE_COMMAND;

    // Configure channel 1 as a clk_dev
    // Mode 0 -> Count Down and Restart
    outb(pit->mode_command, 0b01110000);
    outb(pit->channel[1], 0xFF); // Set the reset value to the maximum
    outb(pit->channel[1], 0xFF);

    // Configure channel 2 for the PC speaker
    // (Muted)
    disconnect_pc_speaker_from_pit();
    outb(pit->mode_command, 0b10110110);
    outb(pit->channel[2], 0x00);
    outb(pit->channel[2], 0x00);

    res = register_clk_dev(&pit->clk_dev, "pit");
    if(res) {
        return res;
    }

    return 0;
}
declare_init_desc(device, pit_init, "Setting up 8253 PIT");
