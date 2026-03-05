
#include <drivers/blk/ide/ide.h>
#include <kanawha/sleep.h>
#include <kanawha/tasklet.h>

#define IDE_BASE_RESERVED_SECTORS (0)

static struct blk_driver ide_primary_blk_driver;
static struct blk_driver ide_secondary_blk_driver;

#define IDE_STATUS_ERR (1 << 0)
#define IDE_STATUS_IDX (1 << 1)
#define IDE_STATUS_CORR (1 << 2)
#define IDE_STATUS_DRQ (1 << 3)
#define IDE_STATUS_SRV (1 << 4)
#define IDE_STATUS_DF (1 << 5)
#define IDE_STATUS_RDY (1 << 6)
#define IDE_STATUS_BSY (1 << 7)

struct ide_command
{
    ilist_node_t list_node;

    enum
    {
        IDE_COMMAND_PENDING,  // This is sitting in a queue waiting to be
                              // started
        IDE_COMMAND_STARTING, // Registers are being written (and the 400ns
                              // delay)
        IDE_COMMAND_RUNNING,  // The device is currently servicing this command
                              // (can poll for BSY)
        IDE_COMMAND_COMPLETE, // This command is completed (check error==0 for
                              // success)
    } state;

    uint8_t command;

    // Argument register values
    uint16_t features_reg;
    uint16_t sector_count_reg;
    uint16_t sector_number_reg;
    uint16_t cylinder_low_reg;
    uint16_t cylinder_high_reg;
    uint8_t drive_head_reg;

    // error register value on completion
    uint16_t error;

    // 0 -> read on DRQ 1 -> write on DRQ
    unsigned drq_write : 1;

    unsigned ignore_rdy : 1;

    // Where to read/write sector data to/from on DRQ
    size_t buflen;
    void *buffer;
};

static inline void
ide_command_target_primary(struct ide_command *cmd)
{
    cmd->drive_head_reg &= ~(1U << 4);
}
__maybe_unused static inline void
ide_command_target_secondary(struct ide_command *cmd)
{
    cmd->drive_head_reg |= (1U << 4);
}
static inline void
ide_command_enable_lba(struct ide_command *cmd)
{
    cmd->drive_head_reg |= (1U << 6);
}

#define IDE_DEV_FLAG_PRIMARY_EXISTS (1ULL << 0)
#define IDE_DEV_FLAG_SECONDARY_EXISTS (1ULL << 1)
#define IDE_DEV_FLAG_LBA48 (1ULL << 2)

struct ide_dev
{
    struct blk_dev primary_blk_dev;
    struct blk_dev secondary_blk_dev;

    char *primary_name;
    char *secondary_name;

    pio_t io_base;
    pio_t ctrl_base;
    unsigned long flags;

    struct tasklet *cmd_tasklet;

    size_t primary_sectors;
    size_t secondary_sectors;

    thread_lock_t command_lock;
    ilist_t queued_commands;
    struct ide_command *current_command;
};

// IO Registers
#define IDE_DATA_REG_OFFSET (0)
#define IDE_FEATURES_REG_OFFSET (1)
#define IDE_ERROR_REG_OFFSET (1)
#define IDE_SECTOR_COUNT_REG_OFFSET (2)
#define IDE_SECTOR_NUMBER_REG_OFFSET (3)
#define IDE_CYLINDER_LOW_REG_OFFSET (4)
#define IDE_CYLINDER_HIGH_REG_OFFSET (5)
#define IDE_DRIVE_HEAD_REG_OFFSET (6)
#define IDE_STATUS_REG_OFFSET (7)
#define IDE_COMMAND_REG_OFFSET (7)
// Ctrl Registers
#define IDE_ALT_STATUS_REG_OFFSET (0)
#define IDE_DEVICE_CTRL_REG_OFFSET (0)

static inline uint16_t
ide_read_data_reg(struct ide_dev *dev)
{
    return inw(dev->io_base + IDE_DATA_REG_OFFSET);
}

static inline void
ide_write_data_reg(struct ide_dev *dev, uint16_t val)
{
    outw(dev->io_base + IDE_DATA_REG_OFFSET, val);
}

static inline uint8_t
ide_read_alt_status_reg(struct ide_dev *dev)
{
    return (uint8_t)inb(dev->ctrl_base + IDE_ALT_STATUS_REG_OFFSET);
}

static inline void
ide_write_device_ctrl_reg(struct ide_dev *dev, uint8_t val)
{
    outb(dev->ctrl_base + IDE_DEVICE_CTRL_REG_OFFSET, val);
}

static inline void
ide_disable_interrupts(struct ide_dev *dev)
{
    ide_write_device_ctrl_reg(dev, 0x02);
}

__maybe_unused static inline void
ide_enable_interrupts(struct ide_dev *dev)
{
    ide_write_device_ctrl_reg(dev, 0x00);
}

#define IDE_ERR_AMNF (1U << 0)
#define IDE_ERR_TKZNF (1U << 1)
#define IDE_ERR_ABRT (1U << 2)
#define IDE_ERR_MCR (1U << 3)
#define IDE_ERR_IDNF (1U << 4)
#define IDE_ERR_MC (1U << 5)
#define IDE_ERR_UNC (1U << 6)
#define IDE_ERR_BBK (1U << 7)

static inline int
ide_launch_current_command_lockless(struct ide_dev *dev)
{
    struct ide_command *cmd = dev->current_command;
    dprintk("ide_launch_current_command...\n");

    cmd->state = IDE_COMMAND_STARTING;
    mbarrier();

    outb(dev->io_base + IDE_DRIVE_HEAD_REG_OFFSET, cmd->drive_head_reg | 0xA0);

    if(dev->flags & IDE_DEV_FLAG_LBA48)
    {
        outb(dev->io_base + IDE_FEATURES_REG_OFFSET,
             (cmd->features_reg >> 8) & 0xFF);
        outb(dev->io_base + IDE_SECTOR_COUNT_REG_OFFSET,
             (cmd->sector_count_reg >> 8) & 0xFF);
        outb(dev->io_base + IDE_SECTOR_NUMBER_REG_OFFSET,
             (cmd->sector_number_reg >> 8) & 0xFF);
        outb(dev->io_base + IDE_CYLINDER_LOW_REG_OFFSET,
             (cmd->cylinder_low_reg >> 8) & 0xFF);
        outb(dev->io_base + IDE_CYLINDER_HIGH_REG_OFFSET,
             (cmd->cylinder_high_reg >> 8) & 0xFF);
    }
    else
    {
        DEBUG_ASSERT((cmd->features_reg & 0xFF00) == 0);
        DEBUG_ASSERT((cmd->sector_count_reg & 0xFF00) == 0);
        DEBUG_ASSERT((cmd->sector_number_reg & 0xFF00) == 0);
        DEBUG_ASSERT((cmd->cylinder_low_reg & 0xFF00) == 0);
        DEBUG_ASSERT((cmd->cylinder_high_reg & 0xFF00) == 0);
    }

    outb(dev->io_base + IDE_FEATURES_REG_OFFSET, cmd->features_reg & 0xFF);
    outb(dev->io_base + IDE_SECTOR_COUNT_REG_OFFSET,
         cmd->sector_count_reg & 0xFF);
    outb(dev->io_base + IDE_SECTOR_NUMBER_REG_OFFSET,
         cmd->sector_number_reg & 0xFF);
    outb(dev->io_base + IDE_CYLINDER_LOW_REG_OFFSET,
         cmd->cylinder_low_reg & 0xFF);
    outb(dev->io_base + IDE_CYLINDER_HIGH_REG_OFFSET,
         cmd->cylinder_high_reg & 0xFF);

    // If the disk takes longer than a second
    // to accept another command, then something is wrong...
    if(cmd->ignore_rdy)
    {
        // This command does not wait for the RDY signal to be asserted
    }
    else
    {
#define TIMEOUT_THRESHOLD 1000
        int disk_is_too_slow_counter = 0;
        while(!(ide_read_alt_status_reg(dev) & IDE_STATUS_RDY))
        {
            if(disk_is_too_slow_counter < TIMEOUT_THRESHOLD)
            {
                clk_delay(msec_to_duration(1));
                disk_is_too_slow_counter++;
            }
            else
            {
                dprintk("ide_launch_current_command: timed out!\n");
                cmd->error = 0xFFFF; // TODO
                mbarrier();
                cmd->state = IDE_COMMAND_COMPLETE;
                return -ETIMEDOUT;
            }
        }
#undef TIMEOUT_THRESHOLD
    }

    dprintk("ide_launch_current_command: drive is ready\n");

    outb(dev->io_base + IDE_COMMAND_REG_OFFSET, cmd->command);

    clk_delay(nsec_to_duration(400));

    cmd->state = IDE_COMMAND_RUNNING;
    mbarrier();

    return 0;
}

static int
ide_dev_timeout_all_pending_commands(struct ide_dev *dev)
{
    int res;
    thread_lock_acquire(&dev->command_lock);
    if(dev->current_command)
    {
        if(dev->current_command->state != IDE_COMMAND_COMPLETE)
        {
            dev->current_command->error = 0xFFFF; // TODO
            mbarrier();
            dev->current_command->state = IDE_COMMAND_COMPLETE;
        }
    }
    ilist_node_t *iter;
    ilist_for_each(iter, &dev->queued_commands)
    {
        struct ide_command *cmd =
            container_of(iter, struct ide_command, list_node);
        cmd->error = 0xFFFF; // TODO
        mbarrier();
        cmd->state = IDE_COMMAND_COMPLETE;
    }
    dev->current_command = NULL;
    ilist_init(&dev->queued_commands); // Reset/Clear the list
    thread_lock_release(&dev->command_lock);
    return 0;
}

static int
ide_handle_running_task(struct ide_dev *dev, struct ide_command *cmd)
{
    // Read the current status to see if we are done
    // (actually read alt status so we don't affect interrupts)
    int completed_job = 0;
    uint8_t status = ide_read_alt_status_reg(dev);
    if((status & IDE_STATUS_ERR) || (status & IDE_STATUS_DF))
    {
        // Something went wrong
        cmd->error = inb(dev->io_base + IDE_ERROR_REG_OFFSET);
        cmd->state = IDE_COMMAND_COMPLETE;
        completed_job = 1;
    }
    else if(status & IDE_STATUS_BSY)
    {
        // Nothing to do
    }
    else if(status & IDE_STATUS_DRQ)
    {
        // Copy data to/from the device

        if(cmd->buflen < 512)
        {
            wprintk("ide_handle_running_task: IDE device requested "
                    "more data but "
                    "command buffer has no more sectors "
                    "(cmd->buflen=%d)!\n",
                    (int)cmd->buflen);
            cmd->error = 0xFFFF; // TODO more specific error
            cmd->state = IDE_COMMAND_COMPLETE;
            completed_job = 1;
        }
        else
        {
            uint16_t *data_ptr = (uint16_t *)cmd->buffer;

            if(cmd->drq_write)
            {
                for(size_t i = 0; i < 256; i++)
                {
                    ide_write_data_reg(dev, data_ptr[i]);
                }
            }
            else
            {
                for(size_t i = 0; i < 256; i++)
                {
                    data_ptr[i] = ide_read_data_reg(dev);
                }
            }

            cmd->buflen -= 512;
            cmd->buffer += 512;

            // Give a delay to allow resetting BSY
            clk_delay(nsec_to_duration(400));
        }
    }
    else
    {
        // The command should be completed
        if(cmd->buflen > 0)
        {
            wprintk("ide_handle_running_task: IDE command finished "
                    "but buffer "
                    "still has 0x%x bytes! (status=0x%x)\n",
                    (unsigned int)cmd->buflen,
                    (unsigned int)status);
            cmd->error = 0xFFFF; // TODO
        }
        else
        {
            // Success
            cmd->error = 0;
        }
        cmd->state = IDE_COMMAND_COMPLETE;
        completed_job = 1;
    }

    return completed_job;
}

static void
ide_check_current_command_task(void *__dev)
{
    int res;
    struct ide_dev *dev = __dev;

    thread_lock_acquire(&dev->command_lock);

    while(1)
    {
        struct ide_command *cmd = dev->current_command;
        if(cmd == NULL || cmd->state == IDE_COMMAND_COMPLETE)
        {
            // We want to keep trying to launch commands until we
            // succeed or the queue is empty
            while(1)
            {
                dev->current_command = NULL;

                ilist_node_t *next = ilist_pop_head(&dev->queued_commands);
                if(next == NULL)
                {
                    // Nothing more to do
                    break;
                }

                cmd = container_of(next, struct ide_command, list_node);
                DEBUG_ASSERT(cmd->state == IDE_COMMAND_PENDING);

                res = ide_launch_current_command_lockless(dev);
                if(res)
                {
                    wprintk("ide_check_current_command_task: "
                            "Failed to launch "
                            "next command! (err=%s)\n",
                            errnostr(res));
                    cmd->error = 0xFFFF; // TODO this should be a more
                                         // specific error condition
                    cmd->state = IDE_COMMAND_COMPLETE;
                    continue; // Try again
                }
            }
        }
        else if(cmd->state == IDE_COMMAND_STARTING)
        {
            // The command is currently getting launched,
            // so the BSY signal might not be asserted, but that does
            // not mean the command has actually finished
        }
        else if(cmd->state == IDE_COMMAND_RUNNING)
        {
            int completed = ide_handle_running_task(dev, cmd);
            if(completed)
            {
                continue;
            }
        }
        break;
    }

    thread_lock_release(&dev->command_lock);
    return;
}

static inline int
ide_queue_command(struct ide_dev *dev, struct ide_command *cmd)
{
    int res;
    thread_lock_acquire(&dev->command_lock);
    cmd->state = IDE_COMMAND_PENDING;
    if(dev->current_command == NULL)
    {
        dev->current_command = cmd;
        res = ide_launch_current_command_lockless(dev);
        if(res)
        {
            thread_lock_release(&dev->command_lock);
            return res;
        }
    }
    else
    {
        ilist_push_tail(&dev->queued_commands, &cmd->list_node);
    }
    thread_lock_release(&dev->command_lock);
    return 0;
}

static int
ide_dev_probe(struct ide_dev *dev)
{
    int res;

    // Read the regular status register
    uint8_t status = inb(dev->io_base + IDE_STATUS_REG_OFFSET);
    if(status == 0xFF)
    {
        // Floating bus, neither drive exists
        dev->flags &=
            ~(IDE_DEV_FLAG_PRIMARY_EXISTS | IDE_DEV_FLAG_SECONDARY_EXISTS);
        return 0;
    }

    // Issue an #IDENTIFY command to both drives
    for(int drive = 0; drive < 2; drive++)
    {

        struct ide_command cmd;
        cmd.command = 0xEC;
        ide_command_enable_lba(&cmd);
        if(drive == 0)
        {
            ide_command_target_primary(&cmd);
        }
        else
        {
            ide_command_target_secondary(&cmd);
        }
        cmd.features_reg = 0x0;
        cmd.sector_number_reg = 0x0;
        cmd.sector_count_reg = 0x0;
        cmd.cylinder_low_reg = 0x0;
        cmd.cylinder_high_reg = 0x0;
        cmd.drq_write = 0;
        cmd.ignore_rdy = 1;

        uint16_t buffer[256];
        cmd.buflen = 512;
        cmd.buffer = buffer;

        res = ide_queue_command(dev, (struct ide_command *)&cmd);
        if(res)
        {
            wprintk("failed to queue #IDENTIFY command for IDE drive\n");
            continue;
        }

#define DELAY_MS 200
#define ATTEMPTS 5
        int timeout_counter = 0;
        duration_t delay = msec_to_duration(DELAY_MS);
        while(cmd.state != IDE_COMMAND_COMPLETE)
        {
            tasklet_run(dev->cmd_tasklet);
            if(timeout_counter >= ATTEMPTS)
            {
                wprintk("#IDENTIFY command timed-out!\n");
                ide_dev_timeout_all_pending_commands(dev);
                break;
            }
            clk_delay(delay);
            timeout_counter++;
        }
#undef DELAY_MS
#undef ATTEMPTS

        if(cmd.error)
        {
            wprintk("#IDENTIFY command failed for IDE drive\n");
            continue;
        }

        if(buffer[83] & (1 << 10))
        {
            if(drive == 1 && !(dev->flags & IDE_DEV_FLAG_LBA48))
            {
                wprintk("IDE mismatch: secondary drive supports "
                        "LBA48 but "
                        "primary does not!\n");
                // Clear the flag so neither uses LBA48
                dev->flags &= ~IDE_DEV_FLAG_LBA48;
            }
            else
            {
                dev->flags |= IDE_DEV_FLAG_LBA48;
            }
        }
        else
        {
            // LBA48 is not supported
            if(dev->flags & IDE_DEV_FLAG_LBA48)
            {
                wprintk("IDE mismatch: primary drive supports "
                        "LBA48 but "
                        "secondary does not!\n");
            }
            dev->flags &= ~IDE_DEV_FLAG_LBA48;
        }

        uint32_t lb28_sectors;
        {
            uint16_t low = buffer[60];
            uint16_t high = buffer[61];
            lb28_sectors = low | ((uint32_t)high << 16);
        }
        uint64_t lb48_sectors = 0;
        {
            lb48_sectors |= ((uint16_t)buffer[100]) << 0;
            lb48_sectors |= ((uint16_t)buffer[101]) << 2;
            lb48_sectors |= ((uint16_t)buffer[102]) << 4;
            lb48_sectors |= ((uint16_t)buffer[103]) << 6;
        }

        size_t sectors;
        if((dev->flags & IDE_DEV_FLAG_LBA48) && lb48_sectors > 0)
        {
            sectors = lb48_sectors;
        }
        else if(lb28_sectors > 0)
        {
            sectors = lb28_sectors;
        }
        else
        {
            // This drive is invalid
            continue;
        }

        if(drive == 0)
        {
            dev->flags |= IDE_DEV_FLAG_PRIMARY_EXISTS;
            dev->primary_sectors = sectors;
        }
        else
        {
            dev->flags |= IDE_DEV_FLAG_SECONDARY_EXISTS;
            dev->secondary_sectors = sectors;
        }
    }

    int can_be_lba28 = 1;
    if(dev->flags & IDE_DEV_FLAG_PRIMARY_EXISTS)
    {
        if(dev->primary_sectors >= 0x10000000)
        {
            can_be_lba28 = 0;
        }
    }
    if(dev->flags & IDE_DEV_FLAG_SECONDARY_EXISTS)
    {
        if(dev->secondary_sectors >= 0x10000000)
        {
            can_be_lba28 = 0;
        }
    }

    // LBA28 is faster so use it if we can.
    if(can_be_lba28)
    {
        dev->flags &= ~IDE_DEV_FLAG_LBA48;
    }

    dprintk("finished probing IDE dev\n");
    return 0;
}

int
ide_dev_register(pio_t io_base,
                 pio_t ctrl_base,
                 const char *name,
                 struct ide_dev **out)
{
    int res;

    struct ide_dev *dev = kzmalloc(sizeof(struct ide_dev), KM_KERNEL);
    if(dev == NULL)
    {
        return -ENOMEM;
    }
    dev->io_base = io_base;
    dev->ctrl_base = ctrl_base;
    dev->flags = 0;

    dev->primary_name = NULL;
    dev->secondary_name = NULL;

    thread_lock_init(&dev->command_lock);
    ilist_init(&dev->queued_commands);
    dev->current_command = NULL;

    ide_disable_interrupts(dev);

    dev->cmd_tasklet = tasklet_create(ide_check_current_command_task, dev);
    if(dev->cmd_tasklet == NULL)
    {
        kfree(dev);
        return -ENOMEM;
    }

    res = ide_dev_probe(dev);
    if(res)
    {
        kfree(dev);
        return res;
    }

    if(!(dev->flags &
         (IDE_DEV_FLAG_PRIMARY_EXISTS | IDE_DEV_FLAG_SECONDARY_EXISTS)))
    {
        kfree(dev);
        return res;
    }

    if(dev->flags & IDE_DEV_FLAG_PRIMARY_EXISTS)
    {
        {
            char namebuf[128];
            snprintk(namebuf, 128, "%s-primary", name);
            namebuf[128 - 1] = '\0';
            dev->primary_name = kstrdup(namebuf);
            if(dev->primary_name == NULL)
            {
                kfree(dev);
                return -ENOMEM;
            }
        }
        dev->primary_blk_dev.driver = &ide_primary_blk_driver;
        res = register_blk_dev(&dev->primary_blk_dev, dev->primary_name);
        if(res)
        {
            kfree(dev->primary_name);
            kfree(dev);
            return res;
        }
    }

    if(dev->flags & IDE_DEV_FLAG_SECONDARY_EXISTS)
    {
        {
            char namebuf[128];
            snprintk(namebuf, 128, "%s-secondary", name);
            namebuf[128 - 1] = '\0';
            dev->secondary_name = kstrdup(namebuf);
            if(dev->secondary_name == NULL)
            {
                if(dev->flags & IDE_DEV_FLAG_PRIMARY_EXISTS)
                {
                    kfree(dev->primary_name);
                    unregister_blk_dev(&dev->primary_blk_dev);
                }
                kfree(dev);
                return -ENOMEM;
            }
        }
        dev->secondary_blk_dev.driver = &ide_secondary_blk_driver;
        res = register_blk_dev(&dev->secondary_blk_dev, dev->secondary_name);
        if(res)
        {
            if(dev->flags & IDE_DEV_FLAG_PRIMARY_EXISTS)
            {
                kfree(dev->primary_name);
                unregister_blk_dev(&dev->primary_blk_dev);
            }
            kfree(dev->secondary_name);
            kfree(dev);
            return res;
        }
    }

    *out = dev;
    return 0;
}

int
ide_dev_unregister(struct ide_dev *dev)
{
    kfree(dev);
    return 0;
}

static int
ide_primary_blk_dev_write(struct blk_dev *blk_dev,
                          void *data,
                          size_t base_sector,
                          size_t num_sectors)
{
    int res;

    struct ide_dev *dev =
        container_of(blk_dev, struct ide_dev, primary_blk_dev);

#define MAX_SECTORS_PER_WRITE 256
    _Static_assert(
        MAX_SECTORS_PER_WRITE <= 256,
        "IDE Device cannot read/write more than 256 sectors at once!");

    size_t num_writes = (num_sectors / MAX_SECTORS_PER_WRITE) +
                        !!(num_sectors % MAX_SECTORS_PER_WRITE);

    { // Bounds Checking
        size_t max_sector_offset = base_sector + num_sectors;
        if(max_sector_offset < base_sector)
        {
            // Overflow
            return -EINVAL;
        }
        else if(!(dev->flags & IDE_DEV_FLAG_LBA48) &&
                (max_sector_offset > ((1ULL << 28) - 1)))
        {
            // Doesn't fit within LBA28
            return -EINVAL;
        }
        else if(max_sector_offset > ((1ULL << 48) - 1))
        {
            // Doesn't fit within LBA48
            return -EINVAL;
        }
    }

    size_t lba_base = base_sector + IDE_BASE_RESERVED_SECTORS;

    for(size_t write_i = 0; write_i < num_writes; write_i++)
    {
        size_t sector_offset = write_i * MAX_SECTORS_PER_WRITE;

        size_t left_to_write = num_sectors - sector_offset;
        size_t sectors_to_write = MIN(left_to_write, MAX_SECTORS_PER_WRITE);

        size_t sec = lba_base + sector_offset;

        struct ide_command cmd;
        if(dev->flags & IDE_DEV_FLAG_LBA48)
        {
            cmd.command = 0x34; // Write Ext.
        }
        else
        {
            cmd.command = 0x30; // Write
        }
        cmd.sector_count_reg = sectors_to_write;
        cmd.sector_number_reg =
            ((sec >> 0) & 0xFF) | (((sec >> 24) & 0xFF) << 8);
        cmd.cylinder_low_reg =
            ((sec >> 8) & 0xFF) | (((sec >> 32) & 0xFF) << 8);
        cmd.cylinder_high_reg =
            ((sec >> 16) & 0xFF) | (((sec >> 40) & 0xFF) << 8);
        cmd.features_reg = 0;
        cmd.drq_write = 1;
        cmd.ignore_rdy = 0;

        cmd.drive_head_reg = 0xF0;
        if(!(dev->flags & IDE_DEV_FLAG_LBA48))
        {
            cmd.drive_head_reg |= ((sec >> 24) & 0xF);
        }

        ide_command_target_primary(&cmd);
        ide_command_enable_lba(&cmd);
        cmd.buffer = data + (512 * sector_offset);
        cmd.buflen = sectors_to_write * 512;

        res = ide_queue_command(dev, (struct ide_command *)&cmd);
        if(res)
        {
            return res;
        }

        while(cmd.state != IDE_COMMAND_COMPLETE)
        {
            tasklet_trigger(dev->cmd_tasklet);
            thread_sleep(msec_to_duration(1), 0);
        }
        if(cmd.error)
        {
            return -EINVAL;
        }
    }

    return 0;

#undef MAX_SECTORS_PER_WRITE
}

static int
ide_primary_blk_dev_read(struct blk_dev *blk_dev,
                         void *data,
                         size_t base_sector,
                         size_t num_sectors)
{
    int res;

    struct ide_dev *dev =
        container_of(blk_dev, struct ide_dev, primary_blk_dev);

#define MAX_SECTORS_PER_READ 256
    _Static_assert(
        MAX_SECTORS_PER_READ <= 256,
        "IDE Device cannot read/write more than 256 sectors at once!");

    size_t num_reads = (num_sectors / MAX_SECTORS_PER_READ) +
                       !!(num_sectors % MAX_SECTORS_PER_READ);

    { // Bounds Checking
        size_t max_sector_offset = base_sector + num_sectors;
        if(max_sector_offset < base_sector)
        {
            // Overflow
            return -EINVAL;
        }
        else if(!(dev->flags & IDE_DEV_FLAG_LBA48) &&
                (max_sector_offset > ((1ULL << 28) - 1)))
        {
            // Doesn't fit within LBA28
            return -EINVAL;
        }
        else if(max_sector_offset > ((1ULL << 48) - 1))
        {
            // Doesn't fit within LBA48
            return -EINVAL;
        }
    }

    size_t lba_base = base_sector + IDE_BASE_RESERVED_SECTORS;

    for(size_t read_i = 0; read_i < num_reads; read_i++)
    {
        size_t sector_offset = read_i * MAX_SECTORS_PER_READ;

        size_t left_to_read = num_sectors - sector_offset;
        size_t sectors_to_read = MIN(left_to_read, MAX_SECTORS_PER_READ);

        size_t sec = lba_base + sector_offset;

        struct ide_command cmd;
        if(dev->flags & IDE_DEV_FLAG_LBA48)
        {
            cmd.command = 0x24; // Read Ext.
        }
        else
        {
            cmd.command = 0x20; // Read
        }
        cmd.sector_count_reg = sectors_to_read == 256 ? 0 : sectors_to_read;
        cmd.sector_number_reg =
            ((sec >> 0) & 0xFF) | (((sec >> 24) & 0xFF) << 8);
        cmd.cylinder_low_reg =
            ((sec >> 8) & 0xFF) | (((sec >> 32) & 0xFF) << 8);
        cmd.cylinder_high_reg =
            ((sec >> 16) & 0xFF) | (((sec >> 40) & 0xFF) << 8);
        cmd.features_reg = 0;
        cmd.drq_write = 0;
        cmd.ignore_rdy = 0;

        cmd.drive_head_reg &= 0xF0;
        if(!(dev->flags & IDE_DEV_FLAG_LBA48))
        {
            cmd.drive_head_reg |= ((sec >> 24) & 0xF);
        }

        ide_command_target_primary(&cmd);
        ide_command_enable_lba(&cmd);
        cmd.buffer = data + (512 * sector_offset);
        cmd.buflen = sectors_to_read * 512;

        res = ide_queue_command(dev, (struct ide_command *)&cmd);
        if(res)
        {
            return res;
        }

        while(cmd.state != IDE_COMMAND_COMPLETE)
        {
            tasklet_trigger(dev->cmd_tasklet);
            thread_sleep(msec_to_duration(1), 0);
        }

        if(cmd.error)
        {
            return -EINVAL;
        }
    }

    //    printk("IDE read completed!\n");
    //    size_t bytelen = num_sectors << 9;
    //    for(size_t i = 0; i < bytelen; i += 4 * 8) {
    //        if(i % 512 == 0) {
    //            printk("sector=%d\n", (int)(i / 512));
    //        }
    //        uint64_t *words = data + i;
    //        for(size_t w = 0; w < 4; w++) {
    //            do_printk("%p ", words[w]);
    //        }
    //        do_printk("\n");
    //    }

    return 0;

#undef MAX_SECTORS_PER_READ
}

static ssize_t
ide_primary_blk_dev_num_sectors(struct blk_dev *blk_dev)
{
    struct ide_dev *dev =
        container_of(blk_dev, struct ide_dev, primary_blk_dev);
    return dev->primary_sectors;
}

static order_t
ide_primary_blk_dev_sector_order(struct blk_dev *blk_dev)
{
    // All IDE Devices have 512 byte sectors
    return 9;
}

static struct blk_driver ide_primary_blk_driver = {
    .read = ide_primary_blk_dev_read,
    .write = ide_primary_blk_dev_write,
    .pread = blk_dev_pread_using_read,
    .pwrite = blk_dev_pwrite_using_write,
    .flush = blk_dev_nop_flush,
    .num_sectors = ide_primary_blk_dev_num_sectors,
    .sector_order = ide_primary_blk_dev_sector_order,
};

static int
ide_secondary_blk_dev_write(struct blk_dev *blk_dev,
                            void *data,
                            size_t base_sector,
                            size_t num_sectors)
{
    struct ide_dev *dev =
        container_of(blk_dev, struct ide_dev, secondary_blk_dev);
    return -EUNIMPL;
}

static int
ide_secondary_blk_dev_read(struct blk_dev *blk_dev,
                           void *data,
                           size_t base_sector,
                           size_t num_sectors)
{
    struct ide_dev *dev =
        container_of(blk_dev, struct ide_dev, secondary_blk_dev);
    return -EUNIMPL;
}

static ssize_t
ide_secondary_blk_dev_num_sectors(struct blk_dev *blk_dev)
{
    struct ide_dev *dev =
        container_of(blk_dev, struct ide_dev, secondary_blk_dev);
    return dev->secondary_sectors;
}

static order_t
ide_secondary_blk_dev_sector_order(struct blk_dev *blk_dev)
{
    // All IDE Devices have 512 byte sectors
    return 9;
}

static struct blk_driver ide_secondary_blk_driver = {
    .read = ide_secondary_blk_dev_read,
    .write = ide_secondary_blk_dev_write,
    .pread = blk_dev_pread_using_read,
    .pwrite = blk_dev_pwrite_using_write,
    .flush = blk_dev_nop_flush,
    .num_sectors = ide_secondary_blk_dev_num_sectors,
    .sector_order = ide_secondary_blk_dev_sector_order,
};
