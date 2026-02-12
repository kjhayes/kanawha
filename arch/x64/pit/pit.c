
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
#include <kanawha/dev/snd.h>

const static pio_t DEFAULT_CHANNEL_0 = 0x40;
const static pio_t DEFAULT_CHANNEL_1 = 0x41;
const static pio_t DEFAULT_CHANNEL_2 = 0x42;
const static pio_t DEFAULT_MODE_COMMAND = 0x43;

#define PIT_HZ ((hz_t)1193182)

static struct pit_dev {
    struct clk_dev clk_dev;
    struct snd_dev snd_dev;
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

__maybe_unused
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

#define PIT_SND_SAMPLING_HZ 100

static struct snd_mode_info
pit_snd_mode =
{
    .sampling_hz = PIT_SND_SAMPLING_HZ, // 10 ms resolution
    .format = SND_FORMAT_FREQ_HZ_16,

    .volume_format = SND_VOLUME_FORMAT_BINARY,
    .volume_min = 0,
    .volume_max = 1,
};

static ssize_t
pit_snd_dev_get_mode(
        struct snd_dev *snd_dev)
{
    return 0;
}

static int
pit_snd_dev_set_mode(
        struct snd_dev *snd_dev,
        size_t mode)
{
    if(mode != 0) {
        return -EINVAL;
    }
    return 0;
}

static struct snd_mode_info *
pit_snd_dev_get_mode_info(
        struct snd_dev *snd_dev,
        size_t mode)
{
    if(mode == 0) {
        return &pit_snd_mode;
    }
    return NULL;
}

static int
pit_snd_dev_put_mode_info(
        struct snd_dev *dev,
        size_t mode,
        struct snd_mode_info *info)
{
    if(mode != 0) {
        return -EINVAL;
    }
    DEBUG_ASSERT(info == &pit_snd_mode);
    return 0;
}

static ssize_t
pit_snd_dev_write_samples(
        struct snd_dev *dev,
        void *buffer,
        size_t buflen,
        unsigned long flags)
{
    // A simple blocking implementation for playing notes

    printk("pit_snd_dev_write_samples!\n");

    struct pit_dev *pit = container_of(dev, struct pit_dev, snd_dev);

    uint16_t *hz_samples = buffer;
    size_t num_samples = buflen / 2;

    if(flags & SND_DEV_WRITE_SAMPLES_NON_BLOCKING) {
        return -EWOULDBLOCK;
    }

    duration_t delay = freq_cycles_to_duration(hz_to_freq(PIT_SND_SAMPLING_HZ), 1);

    for(size_t i = 0; i < num_samples; i++) {
        uint16_t sample = hz_samples[i];
        if(i == 0 || sample == hz_samples[i-1]) {
            freq_t freq = hz_to_freq(sample);
            pc_speaker_set_tone(pit, freq);
        }
        clk_delay(delay);
    }
    disconnect_pc_speaker_from_pit();

    return num_samples * 2;
}

static struct snd_driver
pit_snd_driver = {
    .get_mode = pit_snd_dev_get_mode,
    .set_mode = pit_snd_dev_set_mode,
    .get_mode_info = pit_snd_dev_get_mode_info,
    .put_mode_info = pit_snd_dev_put_mode_info,
    .write_samples = pit_snd_dev_write_samples,
};

static int
pit_init(void)
{
    int res;

    struct pit_dev *pit = &pit_dev;

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

    pit->clk_dev.driver = &pit_clk_driver;
    res = register_clk_dev(&pit->clk_dev, "pit");
    if(res) {
        wprintk("Failed to register PIT as a clk_dev! (err=%s)\n",
                errnostr(res));
    }

    pit->snd_dev.driver = &pit_snd_driver;
    res = register_snd_dev(&pit->snd_dev, "pc-speaker");
    if(res) {
        wprintk("Failed to register PC Speaker as a snd_dev! (err=%s)\n",
                errnostr(res));
    }

    return 0;
}
declare_init_desc(device, pit_init, "Setting up 8253 PIT");
