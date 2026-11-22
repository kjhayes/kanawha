#ifndef __KANAWHA__PAGE_H__
#define __KANAWHA__PAGE_H__

#include <kanawha/types.h>
#include <kanawha/pointer.h>
#include <kanawha/ops.h>

struct page;
struct page_ops;

struct page {
    void __phys *paddr;
    order_t order;
    struct page_ops *ops;
};

#define PAGE_GET_SIG(RET,ARG,...)\
RET(int)

#define PAGE_PUT_SIG(RET,ARG,...)\
RET(int)

#define PAGE_FLUSH_SIG(RET,ARG,...)\
RET(int)

#define PAGE_MARK_DIRTY (1UL<<0)
#define PAGE_MARK_SIG(RET,ARG,...)\
RET(int)\
ARG(unsigned long, status)

#define PAGE_OP_LIST(OP,...)\
OP(flush, PAGE_FLUSH_SIG, ##__VA_ARGS__)\
OP(get, PAGE_GET_SIG, ##__VA_ARGS__)\
OP(put, PAGE_PUT_SIG, ##__VA_ARGS__)\
OP(mark, PAGE_MARK_SIG, ##__VA_ARGS__)\

struct page_ops {
DECLARE_OP_LIST_PTRS(PAGE_OP_LIST, struct page *);
};

DEFINE_OP_LIST_WRAPPERS(
        PAGE_OP_LIST,
        static inline,
        /* No Prefix */,
        page,
        OPS_STRUCT_PTR_ACCESSOR,
        SELF_ACCESSOR
        )

int
page_init(
        struct page *page,
        void __phys *paddr,
        order_t order,
        struct page_ops *ops);
int
page_deinit(
        struct page *page);

void __phys *
page_get_phys(
        struct page *);
order_t
page_get_order(
        struct page *);
size_t
page_get_size(
        struct page *);

// Default Implementations
int
page_nop_flush(
        struct page *page);

// Anonymous Pages

// Returns an anonymous page of zeros,
// with one reference.
// When all references are "put" the page
// will be freed.
struct page *
page_get_anonymous(
        order_t order);

#endif
