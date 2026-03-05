#ifndef __KANAWHA__FS_ISO9660_ISO9660_H__
#define __KANAWHA__FS_ISO9660_ISO9660_H__

#include <kanawha/attribute.h>
#include <kanawha/endian.h>
#include <kanawha/types.h>

#define ISO9660_VOLUME_IDENTIFIER_STRING "CD001"

struct __packed iso9660_dec_datetime
{
    uint8_t year[4];
    uint8_t month[2];
    uint8_t day[2];
    uint8_t hour[2];
    uint8_t min[2];
    uint8_t sec[2];
    uint8_t centisec[2];
    int8_t timezone;
};

#define ISO9660_VOLUME_DESC_TYPE_BOOT_RECORD (0)
#define ISO9660_VOLUME_DESC_TYPE_PRIMARY (1)
#define ISO9660_VOLUME_DESC_TYPE_SUPPLEMENTARY (2)
#define ISO9660_VOLUME_DESC_TYPE_PARTITION (3)

#define ISO9660_VOLUME_DESC_TYPE_TERMINATOR (255)

struct __packed iso9660_volume_desc
{
    int8_t type;
    uint8_t ident[5];
    int8_t version;

    union
    {
        uint8_t raw_data[2041];
        struct __packed
        {
            uint8_t boot_system_ident[32];
            uint8_t boot_ident[32];
            uint8_t boot_system_use[1977];
        } boot_record;
        struct __packed
        {
            uint8_t __unused_0;
            uint8_t system_ident[32];
            uint8_t volume_ident[32];
            uint8_t __unused_1[8];
            lebe32_t volume_space_size;
            uint8_t __unused_2[32];
            lebe16_t volume_set_size;
            lebe16_t volume_seq_num;
            lebe16_t logical_blk_size;
            lebe32_t path_table_size;
            le32_t type_l_path_table_loc;
            le32_t optional_type_l_path_table_loc;
            be32_t type_m_path_table_loc;
            be32_t optional_type_m_path_table_loc;
            uint8_t root_directory_entry[34];
            uint8_t volume_set_ident[128];
            uint8_t publisher_ident[128];
            uint8_t data_prep_ident[128];
            uint8_t application_ident[128];
            uint8_t copyright_ident[37];
            uint8_t abstract_file_ident[37];
            uint8_t bibliographic_file_ident[37];
            struct iso9660_dec_datetime creation_time;
            struct iso9660_dec_datetime modification_time;
            struct iso9660_dec_datetime expiration_time;
            struct iso9660_dec_datetime effective_time;
            int8_t file_structure_version;
            uint8_t __unused_3;
            uint8_t application_used[512];
            uint8_t __resv[653];
        } primary;
    };
};

ASSERT_TYPE_SIZE(struct iso9660_volume_desc, 2048);

#endif
