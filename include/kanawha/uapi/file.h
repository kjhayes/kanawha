#ifndef __KANAWHA__UAPI_FILE_H__
#define __KANAWHA__UAPI_FILE_H__

typedef unsigned long fd_t;

#define FILE_PERM_READ  (1ULL<<0)
#define FILE_PERM_WRITE (1ULL<<1)
#define FILE_PERM_EXEC  (1ULL<<2)

// Writing past the current end of this file should
// extend the size of the file
#define FILE_MODE_WRITE_EXTEND  (1ULL<<0)
// Opening the file should clear the file
#define FILE_MODE_OPEN_TRUNC    (1ULL<<1)
// Non-Blocking File
#define FILE_MODE_NON_BLOCK     (1ULL<<2)
// The file should be closed on "exec"
#define FILE_MODE_CLOSE_ON_EXEC (1ULL<<3)
// Read "fd" on open and interpret path relative to "fd" as a directory
#define FILE_MODE_OPEN_RELATIVE (1ULL<<4)

// Swap dst and src
#define FMOVE_SWAP (0)
// Replace first available descriptor greater than dst with a copy of src
#define FMOVE_DUP  (1)

// faccess Flags
#define FACCESS_MODE_EXACT (0)
#define FACCESS_MODE_SET   (1)
#define FACCESS_MODE_CLEAR (2)

#define FACCESS_NON_BLOCKING  (1ULL<<2)
#define FACCESS_CLOSE_ON_EXEC (1ULL<<3)

// fattr Flags
#define FILE_ATTR_INODE     (1)
#define FILE_ATTR_PAGESIZE  (2)
#define FILE_ATTR_DATASIZE  (3)
#define FILE_ATTR_TYPES     (4)
#define FILE_ATTR_ACCESS    (5)

#define FILE_TYPE_REGULAR   (1ULL<<0)
#define FILE_TYPE_DIRECTORY (1ULL<<1)
#define FILE_TYPE_FIFO      (1ULL<<2)


#endif
