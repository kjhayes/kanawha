
#include <kanawha/dev/term.h>
#include <kanawha/event.h>
#include <kanawha/init.h>
#include <kanawha/tasklet.h>

#define TERM_DEV_BUFLEN (0x1000)
#define TERM_DEV_BUFFER_QUEUE_LEN (8)

static int
term_driver_handle_output(struct term_dev *dev, char c);

static int
term_dev_init(struct term_dev *dev)
{
    waitqueue_init(&dev->read_wq);
    waitqueue_init(&dev->write_wq);

    {
        char namebuf[64];
        snprintk(namebuf, 64, "%s-read", term_dev_get_name(dev));
        namebuf[63] = '\0';
        waitqueue_name(&dev->read_wq, namebuf);
        snprintk(namebuf, 64, "%s-write", term_dev_get_name(dev));
        namebuf[63] = '\0';
        waitqueue_name(&dev->write_wq, namebuf);
    }

    rlock_init(&dev->mode_lock);

    { // Set up the default generic mode for a terminal
        dev->mode.raw = 0;

        dev->mode.echo = 1;

        dev->mode.input_nl_to_cr = 0;
        dev->mode.input_cr_to_nl = 0;
        dev->mode.input_ign_cr = 0;
        dev->mode.input_ign_nl = 0;

        dev->mode.output_cr_to_nl = 0;
        dev->mode.output_nl_to_cr = 0;
        dev->mode.output_nl_to_crnl = 1;
        dev->mode.output_cr_to_crnl = 1;

        dev->mode.input_full_bell = 1;
    }

    dev->buflen = TERM_DEV_BUFLEN;
    dev->buffer_queue_len = TERM_DEV_BUFFER_QUEUE_LEN;

    irq_lock_init(&dev->buffer_queue_lock);
    dev->buffer_queue_head = 0;
    dev->buffer_queue_tail = 0;
    dev->buffer_queue =
        kmalloc(sizeof(struct term_buffer) * dev->buffer_queue_len, KM_KERNEL);
    if(dev->buffer_queue == NULL)
    {
        return -ENOMEM;
    }

    irq_lock_init(&dev->buffer_lock);
    dev->raw_head = 0;
    dev->raw_tail = 0;
    dev->canon_input_offset = 0;
    dev->input_buffer = kmalloc(TERM_DEV_BUFLEN, KM_KERNEL);
    if(dev->input_buffer == NULL)
    {
        kfree(dev->buffer_queue);
        return -ENOMEM;
    }

    dev->canon_output_offset = 0;
    dev->canon_output_buflen = 0;
    dev->canon_output_buffer = NULL;

    printk("term_dev registered: %s\n", term_dev_get_name(dev));
    return 0;
}

static int
term_dev_deinit(struct term_dev *dev)
{
    waitqueue_deinit(&dev->read_wq);
    waitqueue_deinit(&dev->write_wq);
    kfree(dev->input_buffer);
    // TODO drop all buffers in the canonical line queue
    kfree(dev->buffer_queue);
    printk("term_dev unregistered: %s\n", term_dev_get_name(dev));
    return 0;
}

DEFINE_DEV_TYPE(term_dev, dev, term_dev_init, term_dev_deinit);

static inline int
term_driver_raw_input_full_unlocked(struct term_dev *dev)
{
    return (dev->raw_head + 1 == dev->raw_tail) ||
           ((dev->raw_head + 1 == dev->buflen) && (dev->raw_tail == 0));
}

static inline int
term_driver_raw_input_empty_unlocked(struct term_dev *dev)
{
    return (dev->raw_head == dev->raw_tail);
}

int
term_driver_input_empty(struct term_dev *dev)
{
    int res;
    rlock_read_lock(&dev->mode_lock);
    if(dev->mode.raw)
    {
        irq_lock_acquire(&dev->buffer_lock);
        res = term_driver_raw_input_empty_unlocked(dev);
        irq_lock_release(&dev->buffer_lock);
    }
    else
    {
        res = -EUNIMPL;
    }
    rlock_read_unlock(&dev->mode_lock);
    return res;
}

int
term_driver_output_full(struct term_dev *dev)
{
    // TODO
    return 0;
}

static inline int
term_driver_handle_raw_input(struct term_dev *dev, char c)
{
    irq_lock_acquire(&dev->buffer_lock);

    if(term_driver_raw_input_full_unlocked(dev))
    {
        irq_lock_release(&dev->buffer_lock);
        return -ENOMEM;
    }

    dev->input_buffer[dev->raw_head] = c;
    dev->raw_head++;
    if(dev->raw_head >= dev->buflen)
    {
        dev->raw_head = 0;
    }

    irq_lock_release(&dev->buffer_lock);

    wake_all(&dev->read_wq);

    return 0;
}

static inline int
term_driver_is_eol(struct term_dev *dev, char c)
{
    switch(c)
    {
    case '\n':
    case '\r':
    case 0x0: // NUL
    case 0x4: // EOF
        return 1;
    default:
        return 0;
    }
}

static inline int
term_driver_is_erase(struct term_dev *dev, char c)
{
    switch(c)
    {
    case 8:   // BS
    case 127: // DEL
        return 1;
    default:
        return 0;
    }
}

static inline int
term_driver_is_kill(struct term_dev *dev, char c)
{
    switch(c)
    {
    case 25: // Ctrl-X
        return 1;
    default:
        return 0;
    }
}

static inline int
term_driver_buffer_queue_full_unlocked(struct term_dev *dev)
{
    return (dev->buffer_queue_head + 1 == dev->buffer_queue_tail) ||
           ((dev->buffer_queue_head + 1 == dev->buffer_queue_len) &&
            (dev->buffer_queue_tail == 0));
}

static inline int
term_driver_buffer_queue_empty_unlocked(struct term_dev *dev)
{
    return (dev->buffer_queue_head == dev->buffer_queue_tail);
}

static inline int
term_driver_drop_all_buffered_input_unlocked(struct term_dev *dev)
{
    // Needs the buffer_lock and at least the mode read lock.
    if(dev->mode.raw)
    {
        dev->raw_head = 0;
        dev->raw_tail = 0;
    }
    else
    {
        dev->canon_input_offset = 0;
        if(dev->canon_output_buffer)
        {
            kfree(dev->canon_output_buffer);
            dev->canon_output_buffer = NULL;
            dev->canon_output_offset = 0;
            dev->canon_output_buflen = 0;
        }

        while(!term_driver_buffer_queue_empty_unlocked(dev))
        {
            kfree(dev->buffer_queue[dev->buffer_queue_tail].data);
            dev->buffer_queue_tail++;
            if(dev->buffer_queue_tail >= dev->buffer_queue_len)
            {
                dev->buffer_queue_tail = 0;
            }
        }

        dev->buffer_queue_head = 0;
        dev->buffer_queue_tail = 0;
    }
    return 0;
}

static inline int
term_driver_handle_canonical_input(struct term_dev *dev, char c)
{
    int res;

    irq_lock_acquire(&dev->buffer_lock);

    if(term_driver_is_erase(dev, c))
    {
        if(dev->canon_input_offset > 0)
        {
            dev->canon_input_offset--;
        }
        else
        {
            irq_lock_release(&dev->buffer_lock);
            return -ENOMEM; // No "room" for an erase at the start of
                            // the line
        }
        irq_lock_release(&dev->buffer_lock);
        return 0;
    }

    if(term_driver_is_kill(dev, c))
    {
        dev->canon_input_offset = 0;
        irq_lock_release(&dev->buffer_lock);
        return 0;
    }

    if(dev->canon_input_offset >= dev->buflen)
    {
        // No room left in the input buffer
        irq_lock_release(&dev->buffer_lock);
        return -ENOMEM;
    }
    else
    {
        // Push the character into the input buffer
        dev->input_buffer[dev->canon_input_offset] = c;
        dev->canon_input_offset++;
    }

    if(term_driver_is_eol(dev, c))
    {
        // Push the line on to the queue
        wake_all(&dev->read_wq);

        if(term_driver_buffer_queue_full_unlocked(dev))
        {
            irq_lock_release(&dev->buffer_lock);
            return -ENOMEM;
        }

        dev->buffer_queue[dev->buffer_queue_head].len = dev->canon_input_offset;
        dev->buffer_queue[dev->buffer_queue_head].data = dev->input_buffer;
        void *new_buf = kmalloc(dev->buflen, KM_KERNEL);
        if(new_buf == NULL)
        {
            irq_lock_release(&dev->buffer_lock);
            return -ENOMEM;
        }
        else
        {
            dev->input_buffer = new_buf;
            dev->canon_input_offset = 0;
            dev->buffer_queue_head++;
            if(dev->buffer_queue_head >= dev->buffer_queue_len)
            {
                dev->buffer_queue_head = 0;
            }
        }
    }

    irq_lock_release(&dev->buffer_lock);

    return 0;
}

// 0 -> Use "c", 1 -> Drop "c", <0 -> ERROR
static inline int
term_driver_preprocess_input(struct term_dev *dev, char *c)
{
    if(dev->mode.input_nl_to_cr && *c == '\n')
    {
        *c = '\r';
    }
    else if(dev->mode.input_nl_to_cr && *c == '\r')
    {
        *c = '\n';
    }

    if(dev->mode.input_ign_cr && *c == '\r')
    {
        return 1;
    }
    else if(dev->mode.input_ign_nl && *c == '\n')
    {
        return 1;
    }

    return 0;
}

static inline void
term_driver_postprocess_input(struct term_dev *dev, char c, int handle_res)
{
    if(handle_res == -ENOMEM && dev->mode.input_full_bell)
    {
        term_driver_handle_output(dev, '\a'); // Output a BEL
    }
    if(handle_res == 0 && dev->mode.raw == 0 && dev->mode.echo)
    {
        if(term_driver_is_erase(dev, c))
        {
            term_driver_handle_output(dev, '\b');
            term_driver_handle_output(dev, ' ');
            term_driver_handle_output(dev, '\b');
        }
        else
        {
            term_driver_handle_output(dev, c);
        }
    }
}

int
term_driver_provide_input(struct term_dev *dev, char c)
{
    int res;
    rlock_read_lock(&dev->mode_lock);
    res = term_driver_preprocess_input(dev, &c);
    if(res == 0)
    {
        if(dev->mode.raw)
        {
            res = term_driver_handle_raw_input(dev, c);
        }
        else
        {
            res = term_driver_handle_canonical_input(dev, c);
        }
        term_driver_postprocess_input(dev, c, res);
    }
    else
    {
        if(res == 1)
        {
            res = 0;
        }
    }
    rlock_read_unlock(&dev->mode_lock);
    return res;
}

void
term_driver_poke_output(struct term_dev *dev)
{
    wake_all(&dev->write_wq);
}

static ssize_t
term_driver_handle_raw_read_nonblocking(struct term_dev *dev,
                                        void *buffer,
                                        size_t buflen)
{
    irq_lock_acquire(&dev->buffer_lock);

    if(term_driver_raw_input_empty_unlocked(dev))
    {
        irq_lock_release(&dev->buffer_lock);
        return -EWOULDBLOCK;
    }

    size_t cursor = 0;
    while(!term_driver_raw_input_empty_unlocked(dev) && cursor < buflen)
    {
        ((char *)buffer)[cursor] = dev->input_buffer[dev->raw_tail];
        dev->raw_tail++;
        if(dev->raw_tail >= dev->buflen)
        {
            dev->raw_tail = 0;
        }
        cursor++;
    }

    irq_lock_release(&dev->buffer_lock);

    return cursor;
}

static ssize_t
term_driver_handle_canonical_read_nonblocking(struct term_dev *dev,
                                              void *buffer,
                                              size_t amount)
{
    int res;

    dprintk("term_driver_handle_canonical_read_nonblocking\n");

    if(amount <= 0)
    {
        return -EINVAL;
    }

    irq_lock_acquire(&dev->buffer_lock);

    if(dev->canon_output_buffer == NULL)
    {
        if(term_driver_buffer_queue_empty_unlocked(dev))
        {
            irq_lock_release(&dev->buffer_lock);
            return -EWOULDBLOCK;
        }
        else
        {
            dev->canon_output_offset = 0;
            dev->canon_output_buflen =
                dev->buffer_queue[dev->buffer_queue_tail].len;
            dev->canon_output_buffer =
                dev->buffer_queue[dev->buffer_queue_tail].data;
            dev->buffer_queue_tail++;
            if(dev->buffer_queue_tail >= dev->buffer_queue_len)
            {
                dev->buffer_queue_tail = 0;
            }
        }
    }

    // This loop should never really happen, but it is here for safety
    while((dev->canon_output_buffer != NULL) &&
          (dev->canon_output_offset >= dev->canon_output_buflen))
    {
        kfree(dev->canon_output_buffer);
        dev->canon_output_buffer = 0;

        if(term_driver_buffer_queue_empty_unlocked(dev))
        {
            irq_lock_release(&dev->buffer_lock);
            return -EWOULDBLOCK;
        }
        else
        {
            dev->canon_output_offset = 0;
            dev->canon_output_buflen =
                dev->buffer_queue[dev->buffer_queue_tail].len;
            dev->canon_output_buffer =
                dev->buffer_queue[dev->buffer_queue_tail].data;
            dev->buffer_queue_tail++;
            if(dev->buffer_queue_tail >= dev->buffer_queue_len)
            {
                dev->buffer_queue_tail = 0;
            }
        }
    }

    DEBUG_ASSERT(KERNEL_ADDR(dev->canon_output_buffer));
    DEBUG_ASSERT(dev->canon_output_buflen > dev->canon_output_offset);

    size_t room_left = dev->canon_output_buflen - dev->canon_output_offset;
    DEBUG_ASSERT(room_left > 0);

    size_t to_copy = MIN(room_left, amount);

    memcpy(buffer,
           dev->canon_output_buffer + dev->canon_output_offset,
           to_copy);
    dev->canon_output_offset += to_copy;

    if(dev->canon_output_buflen <= dev->canon_output_offset)
    {
        // Eagerly free the buffer (to reduce memory usage)
        kfree(dev->canon_output_buffer);
        dev->canon_output_buffer = NULL;
    }

    irq_lock_release(&dev->buffer_lock);

    dprintk("Read %d bytes canonically!\n", (s_t)to_copy);
    return to_copy;
}

ssize_t
term_driver_read_nonblocking(struct term_dev *dev, void *buffer, size_t buflen)
{
    ssize_t res;
    rlock_read_lock(&dev->mode_lock);
    if(dev->mode.raw)
    {
        res = term_driver_handle_raw_read_nonblocking(dev, buffer, buflen);
    }
    else
    {
        res =
            term_driver_handle_canonical_read_nonblocking(dev, buffer, buflen);
    }
    rlock_read_unlock(&dev->mode_lock);
    return res;
}

static int
term_driver_handle_output(struct term_dev *dev, char c)
{
    if(dev->mode.output_cr_to_nl && c == '\r')
    {
        c = '\n';
    }
    else if(dev->mode.output_nl_to_cr && c == '\n')
    {
        c = '\r';
    }

    if((dev->mode.output_nl_to_crnl && c == '\n') ||
       (dev->mode.output_cr_to_crnl && c == '\r'))
    {
        term_dev_putc(dev, '\r');
        term_dev_putc(dev, '\n');
        return 0;
    }

    return term_dev_putc(dev, c);
}

ssize_t
term_driver_write_nonblocking(struct term_dev *dev, void *buffer, size_t amount)
{
    ssize_t res;

    ssize_t written = 0;
    for(size_t i = 0; i < amount; i++)
    {
        res = term_driver_handle_output(dev, ((char *)buffer)[i]);
        if(res < 0)
        {
            if(res == -EWOULDBLOCK && written > 0)
            {
                // We outputted something (return how much we
                // wrote)
                break;
            }
            else
            {
                // Some other error or we would block without
                // outputting anything
                return res;
            }
        }
        else
        {
            // We outputted a char
            written++;
        }
    }

    return written;
}

int
term_driver_set_raw(struct term_dev *dev, int is_raw)
{
    int res;

    dprintk("Setting Terminal RAW=%d\n", is_raw);

    // Check to make sure we aren't already
    // correctly configured
    int same;
    rlock_read_lock(&dev->mode_lock);
    same = dev->mode.raw == is_raw;
    rlock_read_unlock(&dev->mode_lock);
    if(same)
    {
        return 0;
    }

    rlock_write_lock(&dev->mode_lock);
    irq_lock_acquire(&dev->buffer_lock);

    res = term_driver_drop_all_buffered_input_unlocked(dev);
    if(res)
    {
        irq_lock_release(&dev->buffer_lock);
        rlock_write_unlock(&dev->mode_lock);
        return res;
    }

    if(is_raw)
    {
        dev->raw_head = 0;
        dev->raw_tail = 0;
        dev->mode.raw = 1;
    }
    else
    {
        dev->canon_output_buffer = NULL;
        dev->canon_output_buflen = 0;
        dev->canon_output_offset = 0;
        dev->buffer_queue_head = 0;
        dev->buffer_queue_tail = 0;
        dev->canon_input_offset = 0;
        dev->mode.raw = 0;
    }

    irq_lock_release(&dev->buffer_lock);
    rlock_write_unlock(&dev->mode_lock);
    return 0;
}

#ifdef CONFIG_LOG_TERMDEV_REGISTRY_ON_LAUNCH
static int
dump_term_dev_on_launch(void)
{
    return dump_term_dev_registry(do_printk);
}
declare_init(launch, dump_term_dev_on_launch);
#endif

int
term_dev_cannot_get_baudrate(struct term_dev *dev, baud_t *baud)
{
    return -EINVAL;
}

int
term_dev_cannot_set_baudrate(struct term_dev *dev, baud_t baud)
{
    return -EINVAL;
}

int
term_dev_get_baudrate_zero(struct term_dev *dev, baud_t *baud)
{
    *baud = 0;
    return 0;
}
int
term_dev_set_baudrate_zero(struct term_dev *dev, baud_t baud)
{
    if(baud != 0) {
        return -EINVAL;
    }
    return 0;
}


// Automatically flushing all term_dev at fixed intervals.
static struct periodic_event *periodic_flush_term_dev_event = NULL;
static struct tasklet *periodic_flush_term_dev_tasklet = NULL;
static void
flush_term_dev_callback(struct term_dev *dev, void *state)
{
    term_dev_flush(dev);
}
static void
flush_term_dev_tasklet_callback(void *state)
{
    for_each_term_dev(flush_term_dev_callback, NULL);
}
static void
flush_term_dev_periodic_callback(void *state)
{
    if(periodic_flush_term_dev_tasklet != NULL)
    {
        tasklet_trigger(periodic_flush_term_dev_tasklet);
    }
}
static int
init_periodic_flush_term_dev(void)
{
    periodic_flush_term_dev_tasklet =
        tasklet_create(flush_term_dev_tasklet_callback, NULL);
    if(periodic_flush_term_dev_tasklet == NULL)
    {
        return -ENOMEM;
    }
    tasklet_name(periodic_flush_term_dev_tasklet, "periodic_flush_term_dev");
    periodic_flush_term_dev_event =
        create_periodic_event(msec_to_duration(50),
                              NULL,
                              flush_term_dev_periodic_callback);
    if(periodic_flush_term_dev_event == NULL)
    {
        return -ENOMEM;
    }
    return 0;
}
declare_init_desc(launch, init_periodic_flush_term_dev, "Starting Periodic Flush Of All termdev");
