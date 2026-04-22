#ifndef __ELK_LIBC_POSIX_SYS__MMAN_H__
#define __ELK_LIBC_POSIX_SYS__MMAN_H__

#include <kanawha/mmap.h>
#include <sys/types.h>

#define MAP_FAILED ((void *)(-1ULL))

#define PROT_READ (MMAP_PROT_READ)
#define PROT_WRITE (MMAP_PROT_WRITE)
#define PROT_EXEC (MMAP_PROT_EXEC)
#define PROT_NONE (0)

#define MAP_SHARED (MMAP_SHARED)
#define MAP_PRIVATE (MMAP_PRIVATE)
#define MAP_FIXED (MMAP_FIXED)
#define MAP_ANON (MMAP_ANON)
#define MAP_ANONYMOUS (MMAP_ANON)

#define MS_ASYNC (0b00)
#define MS_SYNC (0b01)
#define MS_INVALIDATE (0b10)

struct posix_typed_mem_info
{
    size_t posix_tmi_length; // Maximum length which may be allocated
                             // from a typed memory object.
};

int
mlock(const void *, size_t);
int
mlockall(int);
void *
mmap(void *, size_t, int, int, int, off_t);
int
mprotect(void *, size_t, int);
int
msync(void *, size_t, int);
int
munlock(const void *, size_t);
int
munlockall(void);
int
munmap(void *, size_t);
int
posix_madvise(void *, size_t, int);
int
posix_mem_offset(const void *restrict,
                 size_t,
                 off_t *restrict,
                 size_t *restrict,
                 int *restrict);
int
posix_typed_mem_get_info(int, struct posix_typed_mem_info *);
int
posix_typed_mem_open(const char *, int, int);
int
shm_open(const char *, int, mode_t);
int
shm_unlink(const char *);

#endif
