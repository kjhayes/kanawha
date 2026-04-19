
#include <drivers/scsi/scsi.h>
#include <drivers/scsi/cdb.h>
#include <kanawha/kmalloc.h>

struct scsi_inquiry_data {
    uint8_t peripheral_device_type : 5;
    uint8_t peripheral_qualifier : 3;
    uint8_t __resv0 : 7;
    uint8_t rmb : 1;
    uint8_t version;
    uint8_t response_data_format : 4;
    uint8_t hisup : 1;
    uint8_t normaca : 1;
    uint8_t __obsolete0 : 2;
    uint8_t additional_length;
    uint8_t protect : 1;
    uint8_t __resv1 : 2;
    uint8_t three_pc : 1;
    uint8_t tpgs : 2;
    uint8_t acc : 1;
    uint8_t sccs : 1;
    uint8_t __obsolete1 : 4;
    uint8_t multip : 1;
    uint8_t vs0 : 1;
    uint8_t encserv : 1;
    uint8_t __obsolete2 : 1;
    uint8_t vs1 : 1;
    uint8_t cmdque : 1;
    uint8_t __obsolete3 : 6;
    be64_t t10_vendor_id;
    uint8_t product_identification[16];
    be32_t product_revision_level;
    be64_t drive_serial_number;
    uint8_t vendor_unique[12];
    uint16_t __resv2;
    be16_t version_descriptors[8];
    uint8_t __resv3[21];
    uint8_t copyright_notice[];
} __packed;

#define SCSI_INQUIRY_PERIPHERAL_QUALIFIER_CONNECTED     (0b000)
#define SCSI_INQUIRY_PERIPHERAL_QUALIFIER_DISCONNECTED  (0b001)
#define SCSI_INQUIRY_PERIPHERAL_QUALIFIER_NOT_SUPPORTED (0b011)

static int
scsi_dev_start(
        struct scsi_dev *dev)
{
    int res;

    struct scsi_cdb_6 cdb = {0};
    cdb.opcode = 0x1B;
    cdb.raw[4] |= 0b1; // Set the START bit

    res = scsi_adaptor_run_physical_command(
            dev->adaptor,
            dev->target,
            &cdb,
            sizeof(cdb),
            NULL, 0,
            NULL, 0);
    if(res) {
        wprintk("SCSI: Failed to start device! (err=%s)\n",
                errnostr(res));
        return res;
    }

    return 0;
}

static int
scsi_dev_inquire(
        struct scsi_dev *dev)
{
    int res;

    uint16_t buflen = 0x1000;
    if(buflen < sizeof(struct scsi_inquiry_data)) {
        buflen = sizeof(struct scsi_inquiry_data);
    }
    void *buffer = kzmalloc(buflen, KM_KERNEL);
    if(buffer == NULL) {
        return -ENOMEM;
    }

    struct scsi_cdb_6 cdb = {0};
    cdb.opcode = 0x12;
    cdb.allocation_length = htobe16(buflen);

    res = scsi_adaptor_run_virtual_command(
            dev->adaptor,
            dev->target,
            &cdb,
            sizeof(cdb),
            buffer,
            buflen,
            NULL,
            0);
    if(res) {
        wprintk("SCSI: Failed to read inquiry data! (err=%s)\n",
                errnostr(res));
        kfree(buffer);
        return 0;
    }

    struct scsi_inquiry_data *data = buffer;

    if(data->response_data_format != 2) {
        wprintk("SCSI INQUIRE: Unrecognized reponse format %d! (expected 2)\n",
                (int)data->response_data_format);
        kfree(buffer);
        return -EINVAL;
    }

    {
        char vendor_name[sizeof(data->t10_vendor_id) + 1];
        memcpy(vendor_name, &data->t10_vendor_id, sizeof(data->t10_vendor_id));
        vendor_name[sizeof(vendor_name)-1] = '\0';
        printk("SCSI: Vendor=\"%s\"\n", vendor_name);
    }

    printk("Read Inquiry Data: qualifier=0x%x\n",
            (u_t)data->peripheral_qualifier);

    kfree(buffer);
    return 0;
}

static int
scsi_dev_probe_capacity(
        struct scsi_dev *dev)
{
    int res;

    int fallback_to_10 = 0;

    do {
        struct resp_16 {
            be64_t lba;
            be32_t lba_byte_length;
            uint8_t prot_en : 1;
            uint8_t p_type : 3;
            uint8_t rc_basis : 2;
            uint8_t __resv0 : 2;
            uint8_t lb_per_phys_exp : 4;
            uint8_t p_i_exponent : 4;
            uint8_t lowest_aligned_lba_0_5 : 6;
            uint8_t lbprz : 1;
            uint8_t lbpme : 1;
            uint8_t lowest_aligned_lba_6_13;
            uint8_t __resv1[16];
        } __packed resp = {0};
        ASSERT_TYPE_SIZE(struct resp_16, 32);

        struct scsi_cdb_16 cdb_16 = {0};
        cdb_16.opcode = 0x9E;
        cdb_16.raw[1] = 0x10;
        cdb_16.allocation_length = htobe32(sizeof(struct resp_16));

        res = scsi_adaptor_run_virtual_command(
                dev->adaptor,
                dev->target,
                &cdb_16,
                sizeof(cdb_16),
                &resp,
                sizeof(resp),
                NULL,
                0);
        if(res) {
            wprintk("SCSI: READ CAPACITY (16) command failed! (err=%s)\n",
                    errnostr(res));
            fallback_to_10 = 1;
            break;
        }

        dev->lba_count = betoh64(resp.lba);
        if(dev->lba_count != 0xFFFFFFFFFFFFFFFFULL) {
            dev->lba_count++;
        } else {
            wprintk("SCSI: Ignoring Final LBA of Drive with 2^64-1 Blocks!\n");
        }

        uint32_t block_length = betoh32(resp.lba_byte_length);

        if(block_length == 0) {
            wprintk("SCSI: MODE SENSE reported an LBA byte length of zero!\n");
            return -EINVAL;
        }

        if(block_length & (block_length-1)) {
            wprintk("SCSI: MODE SENSE reported a non-power-of-two LBA byte length! (len=0x%x)\n",
                    (u_t)block_length);
            return -EINVAL;
        }

        dev->lba_order = ptr_orderof(block_length);
    } while(0);

    if(fallback_to_10) {
        wprintk("SCSI: Falling back to READ CAPACITY (10) command!\n");

        struct scsi_cdb_10 cdb_10 = {0};
        cdb_10.opcode = 0x25;

        struct resp_10 {
            be32_t final_lba;
            be32_t block_length;
        } __packed resp_10 = {0};

        res = scsi_adaptor_run_virtual_command(
                dev->adaptor,
                dev->target,
                &cdb_10,
                sizeof(cdb_10),
                &resp_10,
                sizeof(resp_10),
                NULL,
                0);
        if(res) {
            wprintk("SCSI: Failed to probe device capacity! (err=%s)\n",
                    errnostr(res));
            return res;
        }

        dev->lba_count = ((size_t)betoh32(resp_10.final_lba)) + 1;
        if(dev->lba_count == 0x100000000) {
            wprintk("SCSI: Device may contain more than 2^32 Logical Blocks (Only using for 2^32 LBA)\n");
        }

        { // Issue a mode-sense command to read the LBA size
            struct ms_resp_6 {
                uint8_t mode_data_len;
                uint8_t medium_type;
                uint8_t __resv0 : 4;
                uint8_t dpofua : 1;
                uint8_t __resv1 : 2;
                uint8_t wp : 1;
                uint8_t block_desc_len;
                struct {
                    be32_t number_of_blocks;
                    be32_t lba_byte_length_0_23;
                } descs[1];
            } __packed resp;
            ASSERT_FIELD_OFFSET(struct ms_resp_6, block_desc_len, 3);
            _Static_assert(sizeof(struct ms_resp_6) <= 0xFF,
                    "SCSI: mode sense response structure size "
                    "cannot exceed scsi_cdb_6.allocation_length!");

            struct scsi_cdb_6 ms_cdb_6 = {0};
            ms_cdb_6.opcode = 0x1A;
            ms_cdb_6.raw[2] = 0; // Only return header and parameter block descs
            ms_cdb_6.raw[4] = sizeof(struct ms_resp_6);

            res = scsi_adaptor_run_virtual_command(
                    dev->adaptor,
                    dev->target,
                    &ms_cdb_6,
                    sizeof(ms_cdb_6),
                    &resp,
                    sizeof(resp),
                    NULL,
                    0);
            if(res) {
                wprintk("SCSI: Failed to read device mode-sense for LBA order! (err=%s)\n",
                        errnostr(res));
                return res;
            }

            if(resp.block_desc_len < 8) {
                wprintk("SCSI: MODE SENSE command did not return any block parameters! (block_desc_len=%d)\n",
                        (int)resp.block_desc_len);
                return -EINVAL;
            }

            if(resp.block_desc_len > 8) {
                wprintk("SCSI: MODE SENSE returned multiple block parameter descriptors... (ignoring all but first)\n");
            }

            uint32_t num_blocks = betoh32(resp.descs[0].number_of_blocks);
            uint32_t block_length = betoh32(resp.descs[0].lba_byte_length_0_23);
            block_length &= 0xFFFFFF;

            if(block_length == 0) {
                wprintk("SCSI: MODE SENSE reported an LBA byte length of zero!\n");
                return -EINVAL;
            }

            if(block_length & (block_length-1)) {
                wprintk("SCSI: MODE SENSE reported a non-power-of-two LBA byte length! (len=0x%x)\n",
                        (u_t)block_length);
                return -EINVAL;
            }

            dev->lba_order = ptr_orderof(block_length);
        }
    }

    return 0;
}

static int
scsi_blk_dev_pread(
        struct blk_dev *blk_dev,
        void __phys *data,
        size_t base_sector,
        size_t num_sectors)
{
    int res;

    struct scsi_dev *dev = container_of(blk_dev, struct scsi_dev, blk_dev);

    if(num_sectors > 0xFFFFFFFFUL) {
        wprintk("SCSI: Device cannot read more than 2^32-1 sectors at once!\n");
        return -EINVAL;
    }

    struct scsi_cdb_16 cdb = {0};
    cdb.opcode = 0x88;
    cdb.lba = htobe64(base_sector);
    cdb.xfer_length = htobe32(num_sectors);

    res = scsi_adaptor_run_physical_command(
            dev->adaptor,
            dev->target,
            &cdb,
            sizeof(cdb),
            data,
            (num_sectors << dev->lba_order),
            NULL,
            0);
    if(res) {
        return res;
    }

    return 0;
}

static int
scsi_blk_dev_pwrite(
        struct blk_dev *blk_dev,
        void __phys *data,
        size_t base_sector,
        size_t num_sectors)
{
    int res;
    struct scsi_dev *dev = container_of(blk_dev, struct scsi_dev, blk_dev);

    if(num_sectors > 0xFFFFFFFFUL) {
        wprintk("SCSI: Device cannot write more than 2^32-1 sectors at once!\n");
        return -EINVAL;
    }

    struct scsi_cdb_16 cdb = {0};
    cdb.opcode = 0x8A;
    cdb.lba = htobe64(base_sector);
    cdb.xfer_length = htobe32(num_sectors);

    res = scsi_adaptor_run_physical_command(
            dev->adaptor,
            dev->target,
            &cdb,
            sizeof(cdb),
            NULL,
            0,
            data,
            (num_sectors << dev->lba_order)
            );
    if(res) {
        return res;
    }

    return 0;
}

static int
scsi_blk_dev_flush(
        struct blk_dev *blk_dev,
        unsigned long flags)
{
    int res;
    struct scsi_dev *dev = container_of(blk_dev, struct scsi_dev, blk_dev);

    for(size_t base_sector = 0; base_sector < dev->lba_count; base_sector += (0xFFFFFFFFULL)) {

        uint64_t num_sectors = dev->lba_count - base_sector;
        if(num_sectors > 0xFFFFFFFFULL) {
            num_sectors = 0xFFFFFFFFUL;
        }

        struct scsi_cdb_16 cdb = {0};
        cdb.opcode = 0x91;
        cdb.lba = htobe64(base_sector);
        cdb.xfer_length = htobe32((uint32_t)num_sectors);

        res = scsi_adaptor_run_physical_command(
                dev->adaptor,
                dev->target,
                &cdb,
                sizeof(cdb),
                NULL,
                0,
                NULL,
                0
                );
        if(res) {
            return res;
        }
    }

    return 0;
}

static ssize_t
scsi_blk_dev_num_sectors(struct blk_dev *blk_dev)
{
    struct scsi_dev *dev = container_of(blk_dev, struct scsi_dev, blk_dev);
    return dev->lba_count;
}

static order_t
scsi_blk_dev_sector_order(struct blk_dev *blk_dev)
{
    struct scsi_dev *dev = container_of(blk_dev, struct scsi_dev, blk_dev);
    return dev->lba_order;
}

static struct blk_driver
scsi_blk_driver = {
    .pread = scsi_blk_dev_pread,
    .pwrite = scsi_blk_dev_pwrite,
    .flush = scsi_blk_dev_flush,
    .num_sectors = scsi_blk_dev_num_sectors,
    .sector_order = scsi_blk_dev_sector_order,

    .read = blk_dev_read_using_pread,
    .write = blk_dev_write_using_pwrite,
};

int
scsi_dev_init(
        struct scsi_adaptor *adaptor,
        struct scsi_dev *dev,
        struct scsi_target target)
{
    int res;

    dev->adaptor = adaptor;
    dev->target = target;
    dev->lba_count = 0;
    dev->lba_order = 0;
    dev->name = NULL;

    {
        char namebuf[64+1];
        snprintk(
                namebuf,
                64,
                "%s-%lu-%lu-%lu",
                (ul_t)adaptor->name,
                (ul_t)target.target,
                (ul_t)target.lun
                );
        namebuf[64] = '\0';

        dev->name = kstrdup(namebuf);
    }

    res = scsi_dev_start(dev);
    if(res) {
        kfree(dev->name);
        return res;
    }

    res = scsi_dev_inquire(dev);
    if(res) {
        kfree(dev->name);
        return res;
    }

    res = scsi_dev_probe_capacity(dev);
    if(res) {
        kfree(dev->name);
        return res;
    }

    printk("SCSI: #LBA=%lu, order=%d, capacity=0x%lx\n",
            (ul_t)dev->lba_count,
            (int)dev->lba_order,
            (ul_t)(dev->lba_count << dev->lba_order));

    dev->blk_dev.driver = &scsi_blk_driver;
    res = register_blk_dev(&dev->blk_dev, dev->name);
    if(res) {
        wprintk("SCSI: Failed to register blk_dev \"%s\" (err=%s)\n",
                dev->name,
                errnostr(res));
        kfree(dev->name);
        return res;
    }

    return 0;
}

int
scsi_dev_deinit(struct scsi_dev *dev)
{
    unregister_blk_dev(&dev->blk_dev);
    kfree(dev->name);
    return 0;
}

