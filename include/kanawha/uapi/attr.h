#ifndef __KANAWHA__UAPI_ATTR_H__
#define __KANAWHA__UAPI_ATTR_H__

#define FILE_ATTR_INODE     (1)
#define FILE_ATTR_PAGESIZE  (2)
#define FILE_ATTR_DATASIZE  (3)
#define FILE_ATTR_TYPES     (4)

#define FILE_TYPE_REGULAR   (1ULL<<0)
#define FILE_TYPE_DIRECTORY (1ULL<<1)
#define FILE_TYPE_FIFO      (1ULL<<2)

#endif
