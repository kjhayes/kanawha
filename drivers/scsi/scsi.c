
#include <drivers/scsi/scsi.h>
#include <kanawha/ptree.h>
#include <kanawha/lock.h>
#include <kanawha/endian.h>
#include <kanawha/dma.h>
#include <kanawha/string.h>

DEFINE_LOCAL_IRQ_LOCK(scsi_adaptor_tree_lock);
static DECLARE_PTREE(scsi_adaptor_tree);

struct scsi_cdb_12 {
    uint8_t opcode;
    uint8_t service_action : 5;
    uint8_t misc0 : 3;
    union {
      struct {
        be32_t lba;
        union {
            be32_t xfer_length;
            be32_t param_length;
            be32_t allocation_length;
        } __packed;
      } __packed;
      uint8_t param[8];
    } __packed;
    uint8_t misc1;
    uint8_t control;
} __packed;

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
    }

    return 0;
}
int unregister_scsi_adaptor(struct scsi_adaptor *adaptor)
{
    scsi_adaptor_tree_lock_acquire();
    __maybe_unused struct ptree_node *removed;
    removed = ptree_remove(&scsi_adaptor_tree, adaptor->ptree_node.key);
    scsi_adaptor_tree_lock_release();

    DEBUG_ASSERT(removed == &adaptor->ptree_node);

    return 0;
}

