
#include <kanawha/init.h>
#include <kanawha/dev/blk.h>
#include <drivers/pci/pci.h>
#include <drivers/pci/bar.h>
#include <drivers/pci/cfg.h>
#include <kanawha/kmalloc.h>
#include <kanawha/attribute.h>
#include <kanawha/dma.h>
#include <kanawha/endian.h>
#include <kanawha/sleep.h>

struct nvme_sq_entry;
struct nvme_cq_entry;
struct nvme_command;

#define NVME_SQ_ENTRY_ORDER 6
#define NVME_CQ_ENTRY_ORDER 4

// Command Sets
#define NVME_OPCODE_DELETE_IO_SUBMISSION_QUEUE (0x0)
#define NVME_OPCODE_CREATE_IO_SUBMISSION_QUEUE (0x1)
#define NVME_OPCODE_DELETE_IO_COMPLETION_QUEUE (0x4)
#define NVME_OPCODE_CREATE_IO_COMPLETION_QUEUE (0x5)
#define NVME_OPCODE_IDENTIFY  (0x6)
#define NVME_OPCODE_SELF_TEST (0x14)
//

// Status Code Types
#define NVME_STATUS_CODE_TYPE_GENERIC (0)
#define NVME_STATUS_CODE_TYPE_COMMAND_SPECIFIC (1)
//

// Status Codes
#define NVME_GENERIC_STATUS_CODE_SUCCESSFULL (0)
#define NVME_GENERIC_STATUS_CODE_INVALID_OPCODE (1)
//

struct nvme_queue
{
    irq_lock_t lock;

    size_t queue_idx;
    
    size_t submission_len;
    size_t completion_len;

    dma_addr_t submission_dma;
    dma_addr_t completion_dma;

    struct nvme_sq_entry *submission_data;
    struct nvme_cq_entry *completion_data;

    size_t submission_head;
    size_t submission_tail;

    size_t completion_head;
    // completion_tail indicated by the phase
    unsigned int completion_phase;

    // Ring of all outstanding commands
    size_t outstanding_len;
    size_t outstanding_head;
    struct nvme_command **outstanding_commands;
};

struct nvme_sq_entry {
    union {
        struct {
            uint8_t opcode;
            uint8_t flags;
            le16_t cmd_id;
            le32_t nsid;
            le64_t __resv0;
            le64_t metadata_ptr;
            le64_t data_prp[2];
            le32_t cmd_data[6];
        } __packed;
        le32_t dword[16];
    } __packed;
} __packed;
ASSERT_TYPE_SIZE(struct nvme_sq_entry, 1ULL<<NVME_SQ_ENTRY_ORDER);

struct nvme_cq_entry {
    le32_t cmd_data;
    le32_t __resv0;
    le16_t sq_head_ptr;
    le16_t sq_id;
    le16_t cmd_id;
    uint8_t phase : 1;
    uint8_t status_code : 7;
    uint8_t status_code_type : 3;
    uint8_t retry_delay : 2;
    uint8_t more : 1;
    uint8_t do_not_retry : 1;
} __packed;
ASSERT_TYPE_SIZE(struct nvme_cq_entry, 1ULL<<NVME_CQ_ENTRY_ORDER);

struct nvme_command
{
    enum {
        NVME_COMMAND_STATUS_PENDING = 0,
        NVME_COMMAND_STATUS_SUBMITTED,
        NVME_COMMAND_STATUS_COMPLETED,
    } status;

    union {
        // R/W while Pending
        struct nvme_sq_entry submission;
        // R/W while Completed
        struct nvme_cq_entry completion;
    };

    struct nvme_queue *queue;
};

struct nvme_dev {
    struct pci_func *func;

    // Values read from the capabilities register
    order_t page_order;
    duration_t rdy_timeout;
    size_t doorbell_stride;
    size_t maximum_io_queue_entries;

    struct nvme_queue admin_queue;
    struct nvme_queue io_queue; // could have more than one of these
                                // but I'm going to keep it simple for now -KJH

    void *identify_data;
};

__maybe_unused
static inline uint64_t
nvme_readq(
        struct nvme_dev *dev,
        unsigned int offset)
{
    return letoh64(pci_bar_readq(&dev->func->bars[0], offset));
}

__maybe_unused
static inline void
nvme_writeq(
        struct nvme_dev *dev,
        unsigned int offset,
        uint64_t value)
{
    return pci_bar_writeq(&dev->func->bars[0], offset, htole64(value));
}

static inline uint32_t
nvme_readl(
        struct nvme_dev *dev,
        unsigned int offset)
{
    return letoh32(pci_bar_readl(&dev->func->bars[0], offset));
}

__maybe_unused
static inline void
nvme_writel(
        struct nvme_dev *dev,
        unsigned int offset,
        uint64_t value)
{
    return pci_bar_writel(&dev->func->bars[0], offset, htole32(value));
}

#define NVME_REG_CAP           (0x00)
#define NVME_REG_VS            (0x08)
#define NVME_REG_INTMS         (0x0C)
#define NVME_REG_INTMC         (0x10)
#define NVME_REG_CC            (0x14)
#define NVME_REG_CSTS          (0x1C)
#define NVME_REG_AQA           (0x24)
#define NVME_REG_ASQ           (0x28)
#define NVME_REG_ACQ           (0x30)
#define NVME_REG_DOORBELL_BASE (0x1000)

static int
nvme_queue_init(struct nvme_dev *nvme,
                 struct nvme_queue *queue,
                 int index,
                 size_t submission_len,
                 size_t completion_len,
                 size_t outstanding_len)
{
    int res;

    irq_lock_init(&queue->lock);

    queue->queue_idx = index;

    queue->submission_len = submission_len;
    queue->completion_len = completion_len;
    queue->outstanding_len = outstanding_len;
    if(queue->outstanding_len > 0xFFFF) {
        eprintk("NVME Queue cannot be larger than 0xFFFF entries! (requested=0x%lx)\n",
                (ul_t)queue->outstanding_len);
        return -EINVAL;
    }

    res = dma_alloc(
            queue->submission_len * sizeof(struct nvme_sq_entry),
            nvme->page_order,
            DMA_PHYS_64,
            &queue->submission_dma);
    if(res) {
        return res;
    }

    res = dma_alloc(
            queue->completion_len * sizeof(struct nvme_cq_entry),
            nvme->page_order,
            DMA_PHYS_64,
            &queue->completion_dma);
    if(res) {
        dma_free(queue->submission_dma, queue->submission_len * sizeof(struct nvme_sq_entry));
        return res;
    }

    queue->outstanding_commands = kmalloc(
            sizeof(queue->outstanding_commands[0]) * queue->outstanding_len,
            KM_KERNEL);
    if(queue->outstanding_commands == NULL) {
        dma_free(queue->submission_dma, queue->submission_len * sizeof(struct nvme_sq_entry));
        dma_free(queue->completion_dma, queue->completion_len * sizeof(struct nvme_cq_entry));
        return res;

    }

    queue->submission_head = 0;
    queue->submission_tail = 0;

    queue->completion_head = 0;
    queue->completion_phase = 1;

    queue->submission_data = dma_virt_addr(queue->submission_dma);
    memset(queue->submission_data, 0, queue->submission_len * sizeof(struct nvme_sq_entry));

    queue->completion_data = dma_virt_addr(queue->completion_dma);
    memset(queue->completion_data, 0, queue->completion_len * sizeof(struct nvme_cq_entry));

    queue->outstanding_head = 0;
    memset(queue->outstanding_commands, 0, sizeof(queue->outstanding_commands[0]) * queue->outstanding_len);

    return 0;
}

static int
nvme_queue_deinit(
        struct nvme_dev *nvme,
        struct nvme_queue *queue)
{
    int res;

    res = dma_free(queue->submission_dma,
             queue->submission_len * sizeof(struct nvme_sq_entry));
    if(res) {
        wprintk("Failed to free NVME completion queue dma region (err=%s)\n",
                errnostr(res));
    }
    res = dma_free(queue->completion_dma,
            queue->completion_len * sizeof(struct nvme_cq_entry));
    if(res) {
        wprintk("Failed to free NVME completion queue dma region (err=%s)\n",
                errnostr(res));
    }

    kfree(queue->outstanding_commands);

    return 0;
}

static inline void
nvme_queue_acquire_lock(
        struct nvme_queue *queue)
{
    DEBUG_ASSERT(KERNEL_ADDR(queue));
    irq_lock_acquire(&queue->lock);
}

static inline void
nvme_queue_release_lock(
        struct nvme_queue *queue)
{
    irq_lock_release(&queue->lock);
}

static inline int
nvme_command_init(
        struct nvme_command *cmd)
{
    cmd->status = NVME_COMMAND_STATUS_PENDING;
    return 0;
}

static inline int
nvme_try_submit_command(
        struct nvme_dev *nvme,
        struct nvme_queue *queue,
        struct nvme_command *cmd)
{
    nvme_queue_acquire_lock(queue);

    // Look for space in the outstanding queue
    uint16_t outstanding_slot;
    {
        size_t starting_head = queue->outstanding_head;
        size_t head = starting_head;
        while(1) {
            if(queue->outstanding_commands[head] == NULL) {
                outstanding_slot = head;
                break;
            }
            head++;
            if(head >= queue->outstanding_len) {
                head = 0;
            }
            if(head == starting_head) {
                nvme_queue_release_lock(queue);
                return -EAGAIN;
            }
        }
    }

    // Look for space in the submission queue
    if(queue->submission_head == (queue->submission_tail+1)%queue->submission_len)
    {
        // The submission queue is full
        queue->outstanding_head = outstanding_slot;
        nvme_queue_release_lock(queue);
        return -EAGAIN;
    }

    queue->outstanding_commands[outstanding_slot] = cmd;
    cmd->queue = queue;

    cmd->submission.cmd_id = htole16(outstanding_slot);
    queue->submission_data[queue->submission_tail] = cmd->submission;

    // Increment tail with wrapping
    queue->submission_tail += 1;
    if(queue->submission_tail >= queue->submission_len) {
        queue->submission_tail = 0;
    }

    cmd->status = NVME_COMMAND_STATUS_SUBMITTED;

    // Notify the device
    size_t doorbell_offset = (2*queue->queue_idx)*nvme->doorbell_stride;
    nvme_writel(nvme,
                NVME_REG_DOORBELL_BASE + doorbell_offset,
                queue->submission_tail);

    nvme_queue_release_lock(queue);
    return 0;
}

static inline int
nvme_submit_command(
        struct nvme_dev *nvme,
        struct nvme_queue *queue,
        struct nvme_command *cmd)
{
    int res;
    while(1) {
        res = nvme_try_submit_command(
                nvme,
                queue,
                cmd);
        if(res == -EAGAIN) {
            continue;
        }
        return res;
    }
}

static inline int
nvme_queue_notify_completion(
        struct nvme_queue *queue)
{
    nvme_queue_acquire_lock(queue);

    do {
        struct nvme_cq_entry *cq = &queue->completion_data[queue->completion_head];
        if((cq->phase & 0b1) == queue->completion_phase)
        {
            // This is a valid completion
            uint16_t command_id = letoh16(cq->cmd_id);
            struct nvme_command *cmd = queue->outstanding_commands[command_id];
            if(cmd == NULL) {
                // Something is wrong (most likely with this driver tbh) -KJH
                wprintk("NVME: device posted completion for a command which was not outstanding!\n");
                nvme_queue_release_lock(queue);
                return -EINVAL;
            }

            queue->outstanding_commands[command_id] = NULL;

            uint16_t new_sq_head = letoh16(cq->sq_head_ptr);
            queue->submission_head = new_sq_head;

            DEBUG_ASSERT(cmd->status == NVME_COMMAND_STATUS_SUBMITTED);
            cmd->completion = *cq;
            mbarrier();
            cmd->status = NVME_COMMAND_STATUS_COMPLETED;

            // Notify the device that the completion slot is available
            queue->completion_head++;
            if(queue->completion_head >= queue->completion_len) {
                queue->completion_head = 0;
                queue->completion_phase = !queue->completion_phase;
            }
        }
        else {
            break;
        }
    } while(1);

    nvme_queue_release_lock(queue);
    return 0;
}

static int
nvme_await_command(
        struct nvme_command *cmd)
{
    while(cmd->status == NVME_COMMAND_STATUS_SUBMITTED) {
        //thread_sleep(msec_to_duration(1), 0);
        DEBUG_ASSERT(cmd->queue);
        nvme_queue_notify_completion(cmd->queue);
    }

    if(cmd->status == NVME_COMMAND_STATUS_COMPLETED) {
        return 0;
    } else {
        return -EINVAL;
    }
}

static inline int
nvme_queue_run_command(
        struct nvme_dev *dev,
        struct nvme_queue *queue,
        struct nvme_sq_entry *submission,
        struct nvme_cq_entry *completion)
{
    int res;
    struct nvme_command cmd;
    res = nvme_command_init(&cmd);
    if(res) {
        return res;
    }
    cmd.submission = *submission;
    res = nvme_submit_command(dev, queue, &cmd);
    if(res) {
        return res;
    }
    res = nvme_await_command(&cmd);
    if(res) {
        return res;
    }
    *completion = cmd.completion;
    return 0;
}

static inline int
nvme_dev_run_admin_command(
        struct nvme_dev *dev,
        struct nvme_sq_entry *submission,
        struct nvme_cq_entry *completion)
{
    int res;
    res = nvme_queue_run_command(
            dev,
            &dev->admin_queue,
            submission,
            completion);
    if(res) {
        return res;
    }
    return 0;
}

__maybe_unused
static inline int
nvme_dev_run_io_command(
        struct nvme_dev *dev,
        struct nvme_sq_entry *submission,
        struct nvme_cq_entry *completion)
{
    int res;
    res = nvme_queue_run_command(
            dev,
            &dev->io_queue,
            submission,
            completion);
    if(res) {
        return res;
    }
    return 0;
}

static int
nvme_dev_start_self_test(
        struct nvme_dev *dev,
        int do_long_test)
{
    int res;
    struct nvme_sq_entry submission = {0};
    struct nvme_cq_entry completion;
    submission.opcode = NVME_OPCODE_SELF_TEST;
    submission.nsid = 0xFFFFFFFFUL;
    submission.dword[10] = htole32(do_long_test ? 0x2 : 0x1);
    submission.dword[15] = htole32(0x0);
    res = nvme_dev_run_admin_command(dev, &submission, &completion);
    if(res) {
        return res;
    }

    if(completion.status_code != 0) {
        if(completion.status_code_type == NVME_STATUS_CODE_TYPE_GENERIC) {
            if(completion.status_code == NVME_GENERIC_STATUS_CODE_INVALID_OPCODE) {
                wprintk("NVME: Failed to start self-test due to invalid opcode!\n");
                return 0;
            }
        } else if(completion.status_code_type == NVME_STATUS_CODE_TYPE_COMMAND_SPECIFIC) {
            if(completion.status_code == 0x1D) {
                // The self-test is already running...
                return 0;
            }
        } 
        wprintk("NVME: Failed to start self-test! (status=0x%x)\n",
                (u_t)completion.status_code);
        return -EINVAL;
    }

    return 0;
}

static int
nvme_dev_check_capabilities(struct nvme_dev *nvme)
{
    uint64_t cap_reg = nvme_readq(nvme, NVME_REG_CAP);

    {
        uint64_t min_page_order = ((cap_reg >> 48) & 0xF) + 12;
        uint64_t max_page_order = ((cap_reg >> 52) & 0xF) + 12;
        nvme->page_order = min_page_order;
    }

    {
        uint64_t to = ((cap_reg >> 24) & 0xFF); // [31:24]
        nvme->rdy_timeout = msec_to_duration(500 * to); // encoded in 500ms units
    }

    {
        uint64_t dstrd = (cap_reg>>32) & 0xF; // [35:32]
        nvme->doorbell_stride = 1ULL<<(dstrd+2); // encoded as 2^(dstrd+2)
    }

    {
        uint16_t mqes = cap_reg & 0xFFFF;
        nvme->maximum_io_queue_entries = mqes+1;
    }

    return 0;
}

static int
nvme_dev_reset_disable(struct nvme_dev *nvme)
{
    nvme_writel(nvme, NVME_REG_CC, 0b0); // Set the EN bit to zero

    duration_t timeout = nvme->rdy_timeout;
    duration_t timestep = msec_to_duration(1);

    while(nvme_readl(nvme, NVME_REG_CSTS) & 0b1) {
        if(timeout == 0) {
            return -ETIMEDOUT;
        }
        clk_delay(timestep);
        if(timeout <= timestep) {
            timeout = 0;
        } else {
            timeout -= timestep;
        }
    }

    return 0;
}

static int
nvme_dev_configure_enable(
        struct nvme_dev *nvme)
{
    uint32_t cc_reg = 0x0;

    // Set memory page size field
    cc_reg |= ((((uint32_t)nvme->page_order-12)&0xF)<<7);

    // Set the I/O queue entries sizes
    // Submission Queue Entry is 64-bytes
    cc_reg |= (((uint32_t)6) << 16);
    // Completion Queue Entry is 16-bytes
    cc_reg |= (((uint32_t)4) << 20);

    // Set the command set to be NVM only
    cc_reg |= (((uint32_t)0b000) << 4);

    // Set the "enable" bit
    cc_reg |= 0b1;

    nvme_writel(nvme, NVME_REG_CC, cc_reg);

    duration_t timeout = nvme->rdy_timeout;
    duration_t timestep = msec_to_duration(1);

    while(!(nvme_readl(nvme, NVME_REG_CSTS) & 0b1)) {
        if(timeout == 0) {
            return -ETIMEDOUT;
        }
        clk_delay(timestep); // Wait a ms
        if(timeout <= timestep) {
            timeout = 0;
        } else {
            timeout -= timestep;
        }
    }

    return 0;
}

static int
nvme_dev_init_admin_queues(
        struct nvme_dev *nvme,
        size_t submission_len,
        size_t completion_len,
        size_t outstanding_len)
{
    int res;

    if(submission_len > 0x1000) {
        wprintk("Cannot configure NVME admin submission queue with more than 4096 entries! (requested=%lu)\n",
                submission_len);
        return -EINVAL;
    }
    if(completion_len > 0x1000) {
        wprintk("Cannot configure NVME admin completion queue with more than 4096 entries! (requested=%lu)\n",
                completion_len);
        return -EINVAL;
    }

    res = nvme_queue_init(
            nvme,
            &nvme->admin_queue,
            0,
            submission_len,
            completion_len,
            outstanding_len);
    if(res) {
        wprintk("NVME: Failed to allocate admin queues! (err=%s)\n",
                errnostr(res));
        return res;
    }

    // attributes registers
    uint32_t aqa_reg = 0x0;

    DEBUG_ASSERT(((submission_len-1) & 0xFFF) == (submission_len-1));
    DEBUG_ASSERT(((completion_len-1) & 0xFFF) == (completion_len-1));

    aqa_reg |= (submission_len-1); // [11:0] -> SQ size - 1
    aqa_reg |= (completion_len-1) << 16; // [27:16] -> CQ size - 1

    nvme_writel(nvme, NVME_REG_AQA, aqa_reg);

    // point the device as the queues
    void __phys *sq_phys = dma_phys_addr(nvme->admin_queue.submission_dma);
    void __phys *cq_phys = dma_phys_addr(nvme->admin_queue.completion_dma);

    nvme_writeq(nvme, NVME_REG_ASQ, (uint64_t)sq_phys);
    nvme_writeq(nvme, NVME_REG_ACQ, (uint64_t)cq_phys);

    return 0;
}

static int
nvme_dev_deinit_admin_queues(
        struct nvme_dev *nvme)
{
    int res;
    res = nvme_queue_deinit(
            nvme,
            &nvme->admin_queue);
    if(res) {
        return res;
    }
    return 0;
}

static int
nvme_dev_init_io_queues(
        struct nvme_dev *nvme,
        size_t submission_len,
        size_t completion_len,
        size_t outstanding_len)
{
    int res;

    if(submission_len > nvme->maximum_io_queue_entries) {
        wprintk("NVME: Reducing the size of I/O submission queue from 0x%lx to 0x%lx\n",
                (ul_t)submission_len,
                (ul_t)nvme->maximum_io_queue_entries);
        submission_len = nvme->maximum_io_queue_entries;
    }
    if(completion_len > nvme->maximum_io_queue_entries) {
        wprintk("NVME: Reducing the size of I/O completion queue from 0x%lx to 0x%lx\n",
                (ul_t)completion_len,
                (ul_t)nvme->maximum_io_queue_entries);
        completion_len = nvme->maximum_io_queue_entries;
    }

#define IO_QUEUE_IDX (1)

    res = nvme_queue_init(
            nvme,
            &nvme->io_queue,
            IO_QUEUE_IDX,
            submission_len,
            completion_len,
            outstanding_len);
    if(res) {
        wprintk("NVME: Failed to allocate I/O queues! (err=%s)\n",
                errnostr(res));
        return res;
    }

    {
        void __phys *completion_phys = dma_phys_addr(nvme->io_queue.completion_dma);
        struct nvme_sq_entry submission = {0};
        struct nvme_cq_entry completion;
        submission.opcode = NVME_OPCODE_CREATE_IO_COMPLETION_QUEUE;
        submission.data_prp[0] = htole64((uintptr_t)completion_phys);
        submission.dword[10] = htole32(((completion_len-1) << 16) | (IO_QUEUE_IDX));
        uint16_t flags = 0x0;
        flags |= 0b1; // Physically Contiguous (PRP is direct)
        submission.dword[11] = htole32(flags);

        res = nvme_dev_run_admin_command(
                nvme,
                &submission,
                &completion);
        if(res) {
            wprintk("NVME: Failed to create I/O completion queue!\n");
            nvme_queue_deinit(nvme, &nvme->io_queue);
            return res;
        }
        if(completion.status_code != 0) {
            wprintk("NVME: Failed to create I/O completion queue! (status_type=0x%x) (status=0x%x)\n",
                    (u_t)completion.status_code_type,
                    (u_t)completion.status_code);
            nvme_queue_deinit(nvme, &nvme->io_queue);
            return -EINVAL;
        }
    }

    {
        void __phys *submission_phys = dma_phys_addr(nvme->io_queue.submission_dma);
        struct nvme_sq_entry submission = {0};
        struct nvme_cq_entry completion;
        submission.opcode = NVME_OPCODE_CREATE_IO_SUBMISSION_QUEUE;
        submission.data_prp[0] = htole64((uintptr_t)submission_phys);
        submission.dword[10] = htole32(((submission_len-1) << 16) | (IO_QUEUE_IDX));
        uint16_t flags = 0x0;
        flags |= 0b1; // Physically Contiguous (PRP is direct)
        flags |= (0b10 << 1); // Medium Priority
        flags |= (IO_QUEUE_IDX << 16); // Point this submission queue towards the completion
                                       // queue (NVME does not specify that these come in
                                       // pairs, that is just how this driver functions)
        submission.dword[11] = htole32(flags);

        // "NVM Set Identifier" (set to zero if not understood)
        submission.dword[12] = htole32(0x0);

        res = nvme_dev_run_admin_command(
                nvme,
                &submission,
                &completion);
        if(res) {
            wprintk("NVME: Failed to create I/O submission queue!\n");
            // TODO: In theory we should run a "destory I/O completion queue" command here...
            nvme_queue_deinit(nvme, &nvme->io_queue);
            return res;
        }
        if(completion.status_code != 0) {
            wprintk("NVME: Failed to create I/O submission queue! (status_type=0x%x) (status=0x%x)\n",
                    (u_t)completion.status_code_type,
                    (u_t)completion.status_code);
            // TODO: In theory we should run a "destory I/O completion queue" command here...
            nvme_queue_deinit(nvme, &nvme->io_queue);
            return -EINVAL;
        }
    }

#undef IO_QUEUE_IDX

    return 0;
}

__maybe_unused
static int
nvme_dev_deinit_io_queues(
        struct nvme_dev *nvme)
{
    int res;
    res = nvme_queue_deinit(
            nvme,
            &nvme->io_queue);
    if(res) {
        return res;
    }
    return 0;
}

static int
nvme_pci_probe(
        struct pci_driver *driver,
        struct pci_func *func)
{
    if(func->bars[0].size < 0x38) {
        // The base set of registers cannot fit inside
        // this BAR (not to mention the doorbell registers...)
        wprintk("NVME: PCI Controller does not have a valid BAR 0 size!\n");
        return -EINVAL;
    }

    return 0;
}

static int
nvme_pci_init_device(
        struct pci_driver *driver,
        struct pci_func *func)
{
    int res;
    printk("NVME: init device\n");

    // Order of init/deinit on error is kind of
    // complicated so these variables help out
    int setup_admin_queues = 0;

    struct nvme_dev *nvme = kzmalloc(sizeof(*nvme), KM_KERNEL);
    if(nvme == NULL) {
        return -ENOMEM;
    }

    nvme->func = func;
    func->driver_priv_state = nvme;

    pci_func_raw_enable_bus_master(nvme->func);
    pci_func_raw_enable_mmio(nvme->func);

    {
        uint32_t ver_reg = nvme_readl(nvme, NVME_REG_VS);
        unsigned int ver_major = (ver_reg >> 16) & 0xFFFF;
        unsigned int ver_minor = (ver_reg >> 8) & 0xFF;
        unsigned int ver_tertiary = (ver_reg) & 0xFF;

        printk("NVME: Version %u.%u.%u\n",
                ver_major, ver_minor, ver_tertiary);
        if(ver_major > 2 ||
          (ver_major == 2 && ver_minor > 3) ||
          (ver_major == 2 && ver_minor == 3 && ver_tertiary > 0))
        {
            wprintk("NVME: Device version is too large for current driver!\n");
            res = -EINVAL;
            goto err0;
        }
    }

    res = nvme_dev_check_capabilities(nvme);
    if(res) {
        wprintk("Failed to read NVME device capability register! (err=%s)\n",
                errnostr(res));
        goto err0;

    }

    // Reset the device by disabling it
    res = nvme_dev_reset_disable(nvme);
    if(res) {
        wprintk("Failed to disable NVME device in order to configure it! (err=%s)\n",
                errnostr(res));
        goto err0;
    }

    res = nvme_dev_init_admin_queues(nvme, 32, 32, 32);
    if(res) {
        wprintk("Failed to setup NVME device admin queues! (err=%s)\n",
                errnostr(res));
        goto err0;
    }
    setup_admin_queues = 1;
 
    res = nvme_dev_configure_enable(nvme);
    if(res) {
        wprintk("Failed to configure NVME device! (err=%s)\n",
                errnostr(res));
        goto err0;
    }
    
    // Start a self-test
    res = nvme_dev_start_self_test(nvme, 0);
    if(res) {
        wprintk("NVME: Failed to start device self-test!\n");
        goto err0;
    }

    // Create the I/O Completion Queues
    res = nvme_dev_init_io_queues(nvme, 16, 16, 16);
    if(res) {
        wprintk("NVME: Failed to create I/O queues!\n");
        goto err0;
    }

    return 0;

__maybe_unused
err1:
    nvme_dev_deinit_io_queues(nvme);

err0:
    pci_func_raw_disable_bus_master(nvme->func);
    pci_func_raw_disable_mmio(nvme->func);

    // We do not want to deallocate the queues
    // while the device still has bus mastering enabled.
    if(setup_admin_queues) {
        nvme_dev_deinit_admin_queues(nvme);
    }

    kfree(nvme);

    return res;
}

static int
nvme_pci_deinit_device(
        struct pci_driver *driver,
        struct pci_func *func)
{
    int res;
    printk("NVME: deinit device\n");

    struct nvme_dev *nvme = func->driver_priv_state;

    DEBUG_ASSERT(nvme->func == func);

    pci_func_raw_disable_bus_master(nvme->func);
    pci_func_raw_disable_mmio(nvme->func);

    nvme_dev_deinit_admin_queues(nvme);

    kfree(nvme);

    return 0;
}

static struct pci_id
nvme_pci_ids[] = {
    {
    .class = 0x1,
    .subclass = 0x8,
    .flags = PCI_ID_CHECK_CLASS
	    |PCI_ID_CHECK_SUBCLASS
	    |PCI_ID_IGNORE_DEVICE
	    |PCI_ID_IGNORE_VENDOR,
    },
};

static struct pci_driver_ops
nvme_pci_driver_ops = {
    .probe = &nvme_pci_probe,
    .init_device = &nvme_pci_init_device,
    .deinit_device = &nvme_pci_deinit_device,
};

static struct pci_driver 
nvme_pci_driver = {
    .ops = &nvme_pci_driver_ops,
    .num_ids = sizeof(nvme_pci_ids) / sizeof(struct pci_id),
    .ids = nvme_pci_ids,
};

static int
nvme_pci_register(void)
{
    return register_pci_driver(&nvme_pci_driver);
}
declare_init(device, nvme_pci_register);

