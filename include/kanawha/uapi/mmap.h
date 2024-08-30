#ifndef __KANAWHA__UAPI_MMAP_H__
#define __KANAWHA__UAPI_MMAP_H__

#define MMAP_PROT_READ  (1ULL<<0)
#define MMAP_PROT_WRITE (1ULL<<1)
#define MMAP_PROT_EXEC  (1ULL<<2)

// Mutually Exclusive Types
#define MMAP_SHARED  (0b00 << 0)
#define MMAP_PRIVATE (0b01 << 0)
#define MMAP_ANON    (0b10 << 0)
#define MMAP_ANONYMOUS MMAP_ANON

// "where" is not a suggestion
#define MMAP_FIXED (1ULL << 2)

// If we map on top of another mapping,
// that mapping can be removed, must
// be used with "MAP_FIXED"
#define MMAP_REPLACE (1ULL << 3)

#endif
