
#include <drivers/scsi/scsi.h>
#include <drivers/scsi/cdb.h>
#include <kanawha/ptree.h>
#include <kanawha/lock.h>
#include <kanawha/endian.h>
#include <kanawha/dma.h>
#include <kanawha/string.h>
#include <kanawha/kmalloc.h>

DEFINE_LOCAL_IRQ_LOCK(scsi_adaptor_tree_lock);
static DECLARE_PTREE(scsi_adaptor_tree);

static inline int
scsi_command_error_to_errno(
        struct scsi_command *cmd)
{
    if(cmd->error == 0) {
        return 0;
    }

    return -EINVAL;
}

static int
scsi_adaptor_get_luns(
        struct scsi_adaptor *scsi,
        uint64_t *luns_out,
        uint64_t *max_luns_out)
{
    int res;

    struct scsi_luns_resp {
        be32_t lun_list_length;
        uint32_t __resv;
        uint64_t luns[];
    } __packed;

    size_t bufcount = *max_luns_out;
    uint32_t luns_resp_len = sizeof(struct scsi_luns_resp) + (8 * bufcount);

    struct scsi_target dummy_target = { 0 };
    struct scsi_command *cmd =
        scsi_adaptor_create_command(
            scsi,
            dummy_target,
            SCSI_CREATE_COMMAND_TARGET_REPORT_LUNS);

    struct scsi_cdb_12 cdb = {0};
    cdb.opcode = 0xA0; // REPORT LUNS
    cdb.param[0] = 0x00;
    cdb.allocation_length = htobe32(luns_resp_len);
    cdb.control = 0x00;

    res = scsi_adaptor_write_cdb(
            scsi,
            cmd,
            &cdb,
            sizeof(struct scsi_cdb_12));
    if(res) {
        scsi_adaptor_destroy_command(scsi, cmd);
        return res;
    }

    dma_addr_t luns_resp_dma;
    res = dma_alloc(
            luns_resp_len,
            alignof(struct scsi_luns_resp),
            0,
            &luns_resp_dma);
    if(res) {
        scsi_adaptor_destroy_command(scsi, cmd);
        return res;
    }

    res = scsi_adaptor_point_in_data(
            scsi,
            cmd,
            dma_phys_addr(luns_resp_dma),
            luns_resp_len);
    if(res) {
        dma_free(luns_resp_dma, luns_resp_len);
        scsi_adaptor_destroy_command(scsi, cmd);
        return res;
    }

    res = scsi_adaptor_launch_command(scsi, cmd);
    if(res) {
        dma_free(luns_resp_dma, luns_resp_len);
        scsi_adaptor_destroy_command(scsi, cmd);
        return res;
    }

    res = scsi_adaptor_await_command(scsi, cmd);
    if(res) {
        dma_free(luns_resp_dma, luns_resp_len);
        scsi_adaptor_destroy_command(scsi, cmd);
        return res;
    }

    if(cmd->error) {
        dma_free(luns_resp_dma, luns_resp_len);
        scsi_adaptor_destroy_command(scsi, cmd);
        return -EINVAL;
    }

    struct scsi_luns_resp *resp = dma_virt_addr(luns_resp_dma);
    uint32_t lun_list_length = betoh32(resp->lun_list_length);
    size_t num_luns_avail = lun_list_length / 8;

    size_t read = num_luns_avail > bufcount ? bufcount : num_luns_avail;
    memcpy(luns_out, resp->luns, read * 8);

    *max_luns_out = num_luns_avail;

    dma_free(luns_resp_dma, luns_resp_len);
    scsi_adaptor_destroy_command(scsi, cmd);
    return 0;
}

int register_scsi_adaptor(struct scsi_adaptor *adaptor)
{
    int res;

    ptree_init(&adaptor->device_tree);

    scsi_adaptor_tree_lock_acquire();
    res = ptree_insert_any(&scsi_adaptor_tree, &adaptor->ptree_node);
    scsi_adaptor_tree_lock_release();
    if(res) {
        return res;
    }

    size_t luns_bufcount = 8;
    uint64_t luns_buffer[luns_bufcount];
    size_t luns_avail = luns_bufcount;
    res = scsi_adaptor_get_luns(
            adaptor,
            luns_buffer,
            &luns_avail);
    if(res) {
        wprintk("Failed to read LUN(s) off of SCSI device! (err=%s)\n",
                errnostr(res));
        return res;
    }

    printk("SCSI: Read (%d/%d) LUN(s) off the device!\n",
            (int)(luns_bufcount > luns_avail ? luns_avail : luns_bufcount),
            (int)(luns_avail));
    for(int i = 0; i < (int)(luns_bufcount > luns_avail ? luns_avail : luns_bufcount); i++) {
        uint64_t lun = luns_buffer[i];
        printk("LUN[%d] 0x%lx\n",
                i, lun);

        struct scsi_dev *dev = kmalloc(sizeof(struct scsi_dev), KM_KERNEL);

        res = ptree_insert_any(&adaptor->device_tree, &dev->adaptor_node);
        if(res) {
            kfree(dev);
            continue;
        }

        struct scsi_target target = {
            .target = 0, // TODO stop assuming all devices use target 0
            .lun = lun,
        };

        res = scsi_dev_init(adaptor, dev, target);
        if(res) {
            ptree_remove(&adaptor->device_tree, dev->adaptor_node.key);
            kfree(dev);
            continue;
        }
    }

    return 0;
}
int unregister_scsi_adaptor(struct scsi_adaptor *adaptor)
{
    int res;

    scsi_adaptor_tree_lock_acquire();
    __maybe_unused struct ptree_node *removed;
    removed = ptree_remove(&scsi_adaptor_tree, adaptor->ptree_node.key);
    scsi_adaptor_tree_lock_release();

    {
        while(1) {
            struct ptree_node *node = ptree_get_first(&adaptor->device_tree);
            if(node == NULL) {
                break;
            }
            ptree_remove(&adaptor->device_tree, node->key);
            struct scsi_dev *dev = container_of(node, struct scsi_dev, adaptor_node);

            res = scsi_dev_deinit(dev);
            if(res) {
                panic("Failed to destroy SCSI device during unregister_scsi_adaptor");
            }

            kfree(dev);
        }
    }

    DEBUG_ASSERT(removed == &adaptor->ptree_node);

    return 0;
}

// Helper Functions

int
scsi_adaptor_run_virtual_command(
        struct scsi_adaptor *adaptor,
        struct scsi_target target,
        void *cdb,
        size_t cdb_len,
        void *from_dev_buffer,
        size_t from_dev_buffer_len,
        void *to_dev_buffer,
        size_t to_dev_buffer_len)
{
    int res;

    void __phys *in_phys = 0;
    void __phys *out_phys = 0;

    dma_addr_t in_dma;
    dma_addr_t out_dma;

    if(from_dev_buffer_len > 0) {
        res = dma_alloc(
                from_dev_buffer_len,
                5, // 32-byte aligned
                DMA_PHYS_64,
                &in_dma);
        if(res) {
            return res;
        }
        in_phys = dma_phys_addr(in_dma);
#ifdef CONFIG_DEBUGGING
        void *from_dev = dma_virt_addr(in_dma);
        memset(from_dev, 0, from_dev_buffer_len);
#endif
    }
    if(to_dev_buffer_len > 0) {
        res = dma_alloc(
                to_dev_buffer_len,
                5, // 32-byte aligned
                DMA_PHYS_64,
                &out_dma);
        if(res) {
            if(from_dev_buffer_len > 0) {
                dma_free(in_dma, from_dev_buffer_len);
            }
            return res;
        }
        out_phys = dma_phys_addr(out_dma);
        void *to_dev = dma_virt_addr(out_dma);
        memcpy(to_dev, to_dev_buffer, to_dev_buffer_len);
    }

    res = scsi_adaptor_run_physical_command(
            adaptor,
            target,
            cdb,
            cdb_len,
            in_phys,
            from_dev_buffer_len,
            out_phys,
            to_dev_buffer_len);

    if(from_dev_buffer_len > 0) {
        void *from_dev = dma_virt_addr(in_dma);
        memcpy(from_dev_buffer, from_dev, from_dev_buffer_len);
        dma_free(in_dma, from_dev_buffer_len);
    }
    if(to_dev_buffer_len > 0) {
        dma_free(out_dma, to_dev_buffer_len);
    }

    return res;
}

int
scsi_adaptor_run_physical_command(
        struct scsi_adaptor *adaptor,
        struct scsi_target target,
        void *cdb,
        size_t cdb_len,
        void __phys *from_dev_buffer,
        size_t from_dev_buffer_len,
        void __phys *to_dev_buffer,
        size_t to_dev_buffer_len)
{
    int res;

    struct scsi_command *cmd;
    cmd = scsi_adaptor_create_command(
            adaptor,
            target,
            0);

    res = scsi_adaptor_write_cdb(adaptor, cmd, cdb, cdb_len);
    if(res) {
        scsi_adaptor_destroy_command(adaptor, cmd);
        return res;
    }

    if(from_dev_buffer_len > 0) {
        res = scsi_adaptor_point_in_data(adaptor, cmd, from_dev_buffer, from_dev_buffer_len);
        if(res) {
            scsi_adaptor_destroy_command(adaptor, cmd);
            return res;
        }
    }
    if(to_dev_buffer_len > 0) {
        res = scsi_adaptor_point_out_data(adaptor, cmd, to_dev_buffer, to_dev_buffer_len);
        if(res) {
            scsi_adaptor_destroy_command(adaptor, cmd);
            return res;
        }
    }

    res = scsi_adaptor_launch_command(adaptor, cmd);
    if(res) {
        scsi_adaptor_destroy_command(adaptor, cmd);
        return res;
    }

    res = scsi_adaptor_await_command(adaptor, cmd);
    if(res) {
        scsi_adaptor_destroy_command(adaptor, cmd);
        return res;
    }

    if(cmd->error) {
        res = scsi_command_error_to_errno(cmd);
        scsi_adaptor_destroy_command(adaptor, cmd);
        return res;
    }

    scsi_adaptor_destroy_command(adaptor, cmd);
    return 0;
}

