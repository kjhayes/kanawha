
#include <drivers/scsi/scsi.h>
#include <drivers/virtio/driver.h>
#include <drivers/virtio/queue.h>
#include <drivers/virtio/request.h>
#include <drivers/virtio/virtio.h>
#include <kanawha/init.h>
#include <kanawha/irq.h>
#include <kanawha/kmalloc.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>

/* command-specific response values */
#define VIRTIO_SCSI_S_OK 0
#define VIRTIO_SCSI_S_OVERRUN 1
#define VIRTIO_SCSI_S_ABORTED 2
#define VIRTIO_SCSI_S_BAD_TARGET 3
#define VIRTIO_SCSI_S_RESET 4
#define VIRTIO_SCSI_S_BUSY 5
#define VIRTIO_SCSI_S_TRANSPORT_FAILURE 6
#define VIRTIO_SCSI_S_TARGET_FAILURE 7
#define VIRTIO_SCSI_S_NEXUS_FAILURE 8
#define VIRTIO_SCSI_S_FAILURE 9
/* task_attr */
#define VIRTIO_SCSI_S_SIMPLE 0
#define VIRTIO_SCSI_S_ORDERED 1
#define VIRTIO_SCSI_S_HEAD 2
#define VIRTIO_SCSI_S_ACA 3

#define VIRTIO_SCSI_NAMEBUFLEN (32)

struct virtio_scsi
{
    struct scsi_adaptor scsi_adaptor;

    struct virtio_device *virtio_dev;

    struct virtio_queue *control_queue;
    struct virtio_queue *event_queue;

    uint32_t cdb_size;
    uint32_t sense_size;

    char namebuf[VIRTIO_SCSI_NAMEBUFLEN];

    // There may be multiple request queues
    // but we will use exactly one to maintain
    // ordering.
    struct virtio_queue *request_queue;
};

/*
 * Request Structure
 */

struct virtio_scsi_req_cmd_header
{
    // Device-readable part
    uint8_t lun[8];
    le64_t id;
    uint8_t task_attr;
    uint8_t prio;
    uint8_t crn;
    uint8_t cdb[];
};

struct virtio_scsi_req_cmd_resp
{
    // Device-writable part
    le32_t sense_len;
    le32_t residual;
    le16_t status_qualifier;
    uint8_t status;
    uint8_t response;
    uint8_t sense[];
};

/*
 * Virtio Configuration Fields
 */
struct virtio_scsi_config
{
    le32_t num_queues;
    le32_t seg_max;
    le32_t max_sectors;
    le32_t cmd_per_lun;
    le32_t event_info_size;
    le32_t sense_size;
    le32_t cdb_size;
    le16_t max_channel;
    le16_t max_target;
    le32_t max_lun;
};

struct virtio_scsi_command
{
    struct scsi_command scsi_cmd;
    struct virtio_request *req;

    dma_addr_t hdr_dma;
    size_t hdr_len;
    struct virtio_scsi_req_cmd_header *hdr;

    dma_addr_t resp_dma;
    size_t resp_len;
    struct virtio_scsi_req_cmd_resp *resp;

    size_t in_data_len;
    void __phys *in_data;
    size_t out_data_len;
    void __phys *out_data;
};

static inline struct virtio_scsi *
unwrap_scsi_adaptor(struct scsi_adaptor *adaptor)
{
    return container_of(adaptor, struct virtio_scsi, scsi_adaptor);
}

static inline struct virtio_scsi_command *
unwrap_scsi_command(struct scsi_command *cmd)
{
    return container_of(cmd, struct virtio_scsi_command, scsi_cmd);
}

static struct scsi_command *
virtio_scsi_create_command(struct scsi_adaptor *scsi_adaptor,
                           struct scsi_target target,
                           unsigned long flags)
{
    int res;
    struct virtio_scsi *adaptor = unwrap_scsi_adaptor(scsi_adaptor);

    if(target.target > 0xFF)
    {
        return NULL;
    }
    if(target.lun > 0xFFFF)
    {
        return NULL;
    }

    struct virtio_scsi_command *cmd = kzmalloc(sizeof(*cmd), KM_KERNEL);
    if(cmd == NULL)
    {
        return NULL;
    }

    cmd->req = virtio_request_create(adaptor->request_queue);
    if(cmd->req == NULL)
    {
        kfree(cmd);
        return NULL;
    }

    cmd->hdr_len =
        adaptor->cdb_size + sizeof(struct virtio_scsi_req_cmd_header);
    res = dma_alloc(cmd->hdr_len,
                    alignof(struct virtio_scsi_req_cmd_header),
                    0,
                    &cmd->hdr_dma);
    if(res)
    {
        virtio_request_destroy(cmd->req);
        kfree(cmd);
        return NULL;
    }
    cmd->hdr = dma_virt_addr(cmd->hdr_dma);
    cmd->hdr->id = (uintptr_t)cmd;
    cmd->hdr->crn = 0;
    cmd->hdr->prio = 0;
    cmd->hdr->task_attr = VIRTIO_SCSI_S_SIMPLE;

    cmd->hdr->lun[0] = 0x01;
    cmd->hdr->lun[1] = (uint8_t)target.target;
    cmd->hdr->lun[2] = (uint8_t)((target.lun >> 8) & 0xFF);
    cmd->hdr->lun[3] = (uint8_t)(target.lun & 0xFF);
    memset(&cmd->hdr->lun[4], 0, 4);

    cmd->resp_len =
        adaptor->sense_size + sizeof(struct virtio_scsi_req_cmd_resp);
    res = dma_alloc(cmd->resp_len,
                    alignof(struct virtio_scsi_req_cmd_resp),
                    0,
                    &cmd->resp_dma);
    if(res)
    {
        dma_free(cmd->hdr_dma, cmd->hdr_len);
        virtio_request_destroy(cmd->req);
        kfree(cmd);
        return NULL;
    }
    cmd->resp = dma_virt_addr(cmd->resp_dma);

    cmd->in_data_len = 0;
    cmd->out_data_len = 0;

    cmd->scsi_cmd.status = SCSI_COMMAND_IDLE;
    cmd->scsi_cmd.error = SCSI_ERROR_NONE;

    return &cmd->scsi_cmd;
}

static int
virtio_scsi_write_cdb(struct scsi_adaptor *scsi_adaptor,
                      struct scsi_command *scsi_command,
                      void *cdb,
                      size_t cdb_len)
{
    int res;

    struct virtio_scsi *adaptor = unwrap_scsi_adaptor(scsi_adaptor);
    struct virtio_scsi_command *cmd = unwrap_scsi_command(scsi_command);

    if(cdb_len > adaptor->cdb_size)
    {
        return -EINVAL;
    }

    size_t remaining = adaptor->cdb_size - cdb_len;
    memcpy(cmd->hdr->cdb, cdb, cdb_len);
    memset(cmd->hdr->cdb + cdb_len, 0, remaining);

    return 0;
}

static int
virtio_scsi_point_in_data(struct scsi_adaptor *scsi_adaptor,
                          struct scsi_command *scsi_command,
                          void __phys *in_data_ptr,
                          size_t in_data_len)
{
    struct virtio_scsi *adaptor = unwrap_scsi_adaptor(scsi_adaptor);
    struct virtio_scsi_command *cmd = unwrap_scsi_command(scsi_command);

    cmd->in_data = in_data_ptr;
    cmd->in_data_len = in_data_len;

    return 0;
}

static int
virtio_scsi_point_out_data(struct scsi_adaptor *scsi_adaptor,
                           struct scsi_command *scsi_command,
                           void __phys *out_data_ptr,
                           size_t out_data_len)
{
    struct virtio_scsi *adaptor = unwrap_scsi_adaptor(scsi_adaptor);
    struct virtio_scsi_command *cmd = unwrap_scsi_command(scsi_command);

    cmd->out_data = out_data_ptr;
    cmd->out_data_len = out_data_len;

    return 0;
}

static int
virtio_scsi_launch_command(struct scsi_adaptor *scsi_adaptor,
                           struct scsi_command *scsi_command)
{
    int res;

    struct virtio_scsi *adaptor = unwrap_scsi_adaptor(scsi_adaptor);
    struct virtio_scsi_command *cmd = unwrap_scsi_command(scsi_command);

    // Append all of our buffers to build the request
    res = virtio_request_append_input(cmd->req,
                                      dma_phys_addr(cmd->hdr_dma),
                                      cmd->hdr_len);
    if(res)
    {
        return res;
    }

    if(cmd->out_data_len)
    {
        res = virtio_request_append_input(cmd->req,
                                          cmd->out_data,
                                          cmd->out_data_len);
        if(res)
        {
            return res;
        }
    }

    res = virtio_request_append_output(cmd->req,
                                       dma_phys_addr(cmd->resp_dma),
                                       cmd->resp_len);
    if(res)
    {
        return res;
    }

    if(cmd->in_data_len)
    {
        res = virtio_request_append_output(cmd->req,
                                           cmd->in_data,
                                           cmd->in_data_len);
        if(res)
        {
            return res;
        }
    }

    res = virtio_request_launch(cmd->req);
    if(res)
    {
        return res;
    }

    cmd->scsi_cmd.status = SCSI_COMMAND_LAUNCHED;

    return res;
}

static int
virtio_scsi_await_command(struct scsi_adaptor *scsi_adaptor,
                          struct scsi_command *scsi_command)
{
    int res;
    struct virtio_scsi *adaptor = unwrap_scsi_adaptor(scsi_adaptor);
    struct virtio_scsi_command *cmd = unwrap_scsi_command(scsi_command);

    res = virtio_request_await(cmd->req);
    if(res)
    {
        return res;
    }

    switch(cmd->resp->response)
    {
    case VIRTIO_SCSI_S_OK:
        cmd->scsi_cmd.error = SCSI_ERROR_NONE;
        break;
    default:
        cmd->scsi_cmd.error = SCSI_ERROR_UNKNOWN;
        break;
    }

    cmd->scsi_cmd.status = SCSI_COMMAND_COMPLETED;
    return 0;
}

static int
virtio_scsi_destroy_command(struct scsi_adaptor *scsi_adaptor,
                            struct scsi_command *scsi_command)
{
    struct virtio_scsi *adaptor = unwrap_scsi_adaptor(scsi_adaptor);
    struct virtio_scsi_command *cmd = unwrap_scsi_command(scsi_command);

    virtio_request_destroy(cmd->req);
    dma_free(cmd->hdr_dma, cmd->hdr_len);
    dma_free(cmd->resp_dma, cmd->resp_len);
    kfree(cmd);

    return 0;
}

static struct scsi_adaptor_ops virtio_scsi_adaptor_ops = {
    .create_command = virtio_scsi_create_command,
    .write_cdb = virtio_scsi_write_cdb,
    .point_in_data = virtio_scsi_point_in_data,
    .point_out_data = virtio_scsi_point_out_data,
    .launch_command = virtio_scsi_launch_command,
    .await_command = virtio_scsi_await_command,
    .destroy_command = virtio_scsi_destroy_command,
};

static int
virtio_scsi_probe(struct virtio_driver *driver, struct virtio_device *device)
{
    dprintk("virtio_scsi_probe\n");
    return 0;
}

static int
virtio_scsi_negotiate(struct virtio_driver *driver,
                      struct virtio_device *device)
{
    dprintk("virtio_scsi_negotiate\n");
    return 0;
}

static int
virtio_scsi_init_device(struct virtio_driver *driver,
                        struct virtio_device *device)
{
    int res;

    if(device->num_queues < 3)
    {
        return -EINVAL;
    }

    struct virtio_scsi *scsi = kmalloc(sizeof(struct virtio_scsi), KM_KERNEL);
    if(scsi == NULL)
    {
        return -ENOMEM;
    }
    memset(scsi, 0, sizeof(struct virtio_scsi));

    scsi->virtio_dev = device;
    scsi->control_queue = device->queues[0];
    scsi->event_queue = device->queues[1];
    scsi->request_queue = device->queues[2];

    {
        le32_t _cdb_size;
        res = virtio_device_cfg_readl(
            device,
            offsetof(struct virtio_scsi_config, cdb_size),
            &_cdb_size);
        if(res)
        {
            return res;
        }
        scsi->cdb_size = letoh32(_cdb_size);

        le32_t _sense_size;
        res = virtio_device_cfg_readl(
            device,
            offsetof(struct virtio_scsi_config, sense_size),
            &_sense_size);
        if(res)
        {
            return res;
        }
        scsi->sense_size = letoh32(_sense_size);
    }

    res = virtio_queue_enable(scsi->control_queue);
    if(res)
    {
        kfree(scsi);
        return res;
    }

    res = virtio_queue_enable(scsi->event_queue);
    if(res)
    {
        virtio_queue_disable(scsi->control_queue);
        kfree(scsi);
        return res;
    }
    res = virtio_queue_enable(scsi->request_queue);
    if(res)
    {
        virtio_queue_disable(scsi->control_queue);
        virtio_queue_disable(scsi->event_queue);
        kfree(scsi);
        return res;
    }

    {
        static unsigned long id = 0;
        snprintk(scsi->namebuf, VIRTIO_SCSI_NAMEBUFLEN, "virtio-scsi-%ld", id);
        id++;
        scsi->namebuf[VIRTIO_SCSI_NAMEBUFLEN - 1] = '\0';
    }

    scsi->scsi_adaptor.ops = &virtio_scsi_adaptor_ops;
    res = register_scsi_adaptor(&scsi->scsi_adaptor, scsi->namebuf);
    if(res)
    {
        virtio_queue_disable(scsi->control_queue);
        virtio_queue_disable(scsi->event_queue);
        virtio_queue_disable(scsi->request_queue);
        kfree(scsi);
        return res;
    }

    return 0;
}

static int
virtio_scsi_deinit_device(struct virtio_driver *driver,
                          struct virtio_device *device)
{
    return -EUNIMPL;
}

static struct virtio_driver_ops virtio_scsi_virtio_driver_ops = {
    .probe = virtio_scsi_probe,
    .negotiate = virtio_scsi_negotiate,
    .init_device = virtio_scsi_init_device,
    .deinit_device = virtio_scsi_deinit_device,
};

static uint16_t virtio_scsi_virtio_ids[] = {
    8,
};

static struct virtio_driver virtio_scsi_virtio_driver = {
    .ops = &virtio_scsi_virtio_driver_ops,
    .num_ids = sizeof(virtio_scsi_virtio_ids) / sizeof(uint16_t),
    .ids = virtio_scsi_virtio_ids,
};

static int
register_virtio_scsi_driver(void)
{
    return register_virtio_driver(&virtio_scsi_virtio_driver);
}
declare_init_desc(device,
                  register_virtio_scsi_driver,
                  "Registering Virtio SCSI Driver");
