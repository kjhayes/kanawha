#ifndef __KANAWHA__FS_CPIO_CPIO_H__
#define __KANAWHA__FS_CPIO_CPIO_H__

#include <kanawha/types.h>
#include <kanawha/attribute.h>

typedef enum {
    CPIO_ASCII,
    CPIO_BINARY,
} cpio_type_t;

#define CPIO_HEADER_MAGIC 0x71c7

struct __packed cpio_binary_header {
    uint16_t c_magic;
    uint16_t c_dev;
    uint16_t c_ino;
    uint16_t c_mode;
    uint16_t c_uid;
    uint16_t c_gid;
    uint16_t c_nlink;
    uint16_t c_rdev;
    uint16_t c_mtime[2];
    uint16_t c_namesize;
    uint16_t c_filesize[2];
};

struct cpio_header {
    struct cpio_binary_header binary;
};

#endif
