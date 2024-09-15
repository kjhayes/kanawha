#ifndef __KANAWHA__BITMAP_H__
#define __KANAWHA__BITMAP_H__

#include <kanawha/stdint.h>
#include <kanawha/assert.h>

#define BITS_PER_LONG (sizeof(unsigned long)*8)

#define DECLARE_BITMAP(name, entries)\
    unsigned long (name)[\
        ((entries)/BITS_PER_LONG) + (((entries) % BITS_PER_LONG)!=0)\
    ]

static inline int
bitmap_check(unsigned long *bitmap, size_t bit)
{
    return (bitmap[bit/BITS_PER_LONG] >> (bit%BITS_PER_LONG)) & 1;
}

static inline void
bitmap_set(unsigned long *bitmap, size_t bit)
{
    bitmap[bit/BITS_PER_LONG] |= 1UL<<(bit%BITS_PER_LONG);
}

static inline void
bitmap_clear(unsigned long *bitmap, size_t bit)
{
    bitmap[bit/BITS_PER_LONG] &= ~(1UL<<(bit%BITS_PER_LONG));
}

// Search functions for a bitmap with "num_entries" number of bits,
// returns bit index found or "num_entries" if none are found.
size_t bitmap_find_first_set(unsigned long *bitmap, size_t num_entries);
size_t bitmap_find_first_clear(unsigned long *bitmap, size_t num_entries);

size_t bitmap_find_set_range(unsigned long *bitmap, size_t num_entries, size_t num_needed);
size_t bitmap_find_clear_range(unsigned long *bitmap, size_t num_entries, size_t num_needed);

#endif
