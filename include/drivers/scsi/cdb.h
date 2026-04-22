#ifndef __KANAWHA__SCSI_CDB_H__
#define __KANAWHA__SCSI_CDB_H__

#include <kanawha/assert.h>
#include <kanawha/attribute.h>
#include <kanawha/endian.h>
#include <kanawha/types.h>

struct scsi_cdb_6
{
    union
    {
        struct
        {
            uint8_t opcode;
            union
            {
                uint8_t param[4];
                struct
                {
                    uint8_t lba[3];
                    union
                    {
                        uint8_t xfer_length;
                        uint8_t param_length;
                        uint8_t allocation_length;
                    } __packed;
                } __packed;
            } __packed;
            uint8_t control;
        } __packed;
        uint8_t raw[6];
    } __packed;
} __packed;
ASSERT_TYPE_SIZE(struct scsi_cdb_6, 6);

struct scsi_cdb_10
{
    union
    {
        struct
        {
            uint8_t opcode;
            uint8_t service_action : 5;
            uint8_t misc0 : 3;
            be32_t lba;
            uint8_t misc1;
            union
            {
                be16_t xfer_length;
                be16_t param_length;
                be16_t allocation_length;
            };
            uint8_t control;
        } __packed;
        uint8_t raw[10];
    };
} __packed;
ASSERT_TYPE_SIZE(struct scsi_cdb_10, 10);

struct scsi_cdb_12
{
    union
    {
        struct
        {
            uint8_t opcode;
            uint8_t service_action : 5;
            uint8_t misc0 : 3;
            union
            {
                struct
                {
                    be32_t lba;
                    union
                    {
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
        uint8_t raw[12];
    } __packed;
} __packed;
ASSERT_TYPE_SIZE(struct scsi_cdb_12, 12);

struct scsi_cdb_16
{
    union
    {
        struct
        {
            uint8_t opcode;
            uint8_t misc0;
            be64_t lba;
            union
            {
                be32_t xfer_length;
                be32_t param_length;
                be32_t allocation_length;
            } __packed;
            uint8_t misc1;
            uint8_t control;
        } __packed;
        uint8_t raw[16];
    } __packed;
} __packed;
ASSERT_TYPE_SIZE(struct scsi_cdb_16, 16);

#endif
