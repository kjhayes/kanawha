#ifndef __KANAWHA__KMALLOC_H__
#define __KANAWHA__KMALLOC_H__

#include <kanawha/stdint.h>

#define KMALLOC_ALIGN_ORDER 4

// size is both an input and an output,
// but as an output it must be >= the input value
void * kmalloc_specific(order_t align_order, size_t *size);
int kfree_specific(void *addr, size_t size);

// Wrappers on the k*_specific functions that assume a maximum alignment
// for the architecture and track the size internally
void * kmalloc(size_t size);
void kfree(void * addr);

#endif
