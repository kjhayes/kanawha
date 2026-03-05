#ifndef __KANAWHA__UAPI_MMAP_H__
#define __KANAWHA__UAPI_MMAP_H__

// Mutually Exclusive Types
#define MMAP_FLAGS_TYPE_MASK 0b11
#define MMAP_SHARED (0b00 << 0)
#define MMAP_PRIVATE (0b01 << 0)
#define MMAP_ANON (0b10 << 0)
#define MMAP_ANONYMOUS MMAP_ANON

#define MMAP_EXACT (1ULL << 2)
#define MMAP_PROT_READ (1ULL << 3)
#define MMAP_PROT_WRITE (1ULL << 4)
#define MMAP_PROT_EXEC (1ULL << 5)

#endif
