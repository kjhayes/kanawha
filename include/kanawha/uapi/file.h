#ifndef __KANAWHA__UAPI_FILE_H__
#define __KANAWHA__UAPI_FILE_H__

typedef unsigned long fd_t;
#define NULL_FD (fd_t)(0)

#define FILE_PERM_READ  (1ULL<<0)
#define FILE_PERM_WRITE (1ULL<<1)
#define FILE_PERM_EXEC  (1ULL<<2)

// Writing past the current end of this file should
// extend the size of the file
#define FILE_MODE_WRITE_EXTEND (1ULL<<0)
// Opening the file should clear the file
#define FILE_MODE_OPEN_TRUNC   (1ULL<<1)

#endif
