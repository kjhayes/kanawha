#ifndef __KANAWHA__DRIVERS_BLK_IDE_ATA_H__
#define __KANAWHA__DRIVERS_BLK_IDE_ATA_H__

#include <kanawha/ops.h>

struct ata_channel;

// These are not offsets for any physical hardware, just unique ID's
#define ATA_REG_DATA (0)
#define ATA_REG_ERROR (1)
#define ATA_REG_FEATURES (2)
#define ATA_REG_SECTOR_COUNT (3)
#define ATA_REG_SECTOR_NUMBER (4)
#define ATA_REG_LBA_LOW (5)
#define ATA_REG_CYLINDER_LOW (6)
#define ATA_REG_LBA_MID (7)
#define ATA_REG_CYLINDER_HIGH (8)
#define ATA_REG_LBA_HIGH (9)
#define ATA_REG_DRIVE_HEAD (10)
#define ATA_REG_STATUS (11)
#define ATA_REG_COMMAND (12)
#define ATA_REG_ALT_STATUS (13)
#define ATA_REG_DEVICE_CONTROL (14)
#define ATA_REG_DRIVE_ADDRESS (15)

#define ATA_LEGACY_PRIMARY_IO_BASE (0x1F0)
#define ATA_LEGACY_PRIMARY_CTRL_BASE (0x3F6)
#define ATA_LEGACY_SECONDARY_IO_BASE (0x170)
#define ATA_LEGACY_SECONDARY_CTRL_BASE (0x376)

#define ATA_CHANNEL_READB_SIG(RET, ARG, ...)                                   \
    RET(int)                                                                   \
    ARG(int, reg)                                                              \
    ARG(uint8_t *, out)

#define ATA_CHANNEL_READW_SIG(RET, ARG, ...)                                   \
    RET(int)                                                                   \
    ARG(int, reg)                                                              \
    ARG(uint16_t *, out)

#define ATA_CHANNEL_READL_SIG(RET, ARG, ...)                                   \
    RET(int)                                                                   \
    ARG(int, reg)                                                              \
    ARG(uint32_t *, out)

#define ATA_CHANNEL_READQ_SIG(RET, ARG, ...)                                   \
    RET(int)                                                                   \
    ARG(int, reg)                                                              \
    ARG(uint64_t *, out)

#define ATA_CHANNEL_WRITEB_SIG(RET, ARG, ...)                                  \
    RET(int)                                                                   \
    ARG(int, reg)                                                              \
    ARG(uint8_t, value)

#define ATA_CHANNEL_WRITEW_SIG(RET, ARG, ...)                                  \
    RET(int)                                                                   \
    ARG(int, reg)                                                              \
    ARG(uint16_t, value)

#define ATA_CHANNEL_WRITEW_SIG(RET, ARG, ...)                                  \
    RET(int)                                                                   \
    ARG(int, reg)                                                              \
    ARG(uint16_t, value)

#define ATA_CHANNEL_WRITEL_SIG(RET, ARG, ...)                                  \
    RET(int)                                                                   \
    ARG(int, reg)                                                              \
    ARG(uint32_t, value)

#define ATA_CHANNEL_WRITEQ_SIG(RET, ARG, ...)                                  \
    RET(int)                                                                   \
    ARG(int, reg)                                                              \
    ARG(uint64_t, value)

#define ATA_CHANNEL_OP_LIST(OP, ...)                                           \
    OP(readb, ATA_CHANNEL_READB_SIG, ##__VA_ARGS__)                            \
    OP(readw, ATA_CHANNEL_READW_SIG, ##__VA_ARGS__)                            \
    OP(readl, ATA_CHANNEL_READL_SIG, ##__VA_ARGS__)                            \
    OP(readq, ATA_CHANNEL_READQ_SIG, ##__VA_ARGS__)                            \
    OP(writeb, ATA_CHANNEL_WRITEB_SIG, ##__VA_ARGS__)                          \
    OP(writew, ATA_CHANNEL_WRITEW_SIG, ##__VA_ARGS__)                          \
    OP(writel, ATA_CHANNEL_WRITEL_SIG, ##__VA_ARGS__)                          \
    OP(writeq, ATA_CHANNEL_WRITEQ_SIG, ##__VA_ARGS__)

struct ata_channel_ops
{
    DECLARE_OP_LIST_PTRS(ATA_CHANNEL_OP_LIST, struct ata_channel *);
};

struct ata_channel
{
    struct ata_channel_ops *ops;
};

DEFINE_OP_LIST_WRAPPERS(ATA_CHANNEL_OP_LIST,
                        static inline,
                        /* No Prefix */,
                        ata_channel,
                        OPS_STRUCT_PTR_ACCESSOR,
                        SELF_ACCESSOR);

#endif
