#ifndef __KANAWHA__UAPI_FILE_H__
#define __KANAWHA__UAPI_FILE_H__

typedef unsigned long fd_t;
#define NULL_FD (fd_t)(0)

#define FILE_PERM_READ  (1ULL<<0)
#define FILE_PERM_WRITE (1ULL<<1)
#define FILE_PERM_EXEC  (1ULL<<2)

#endif
