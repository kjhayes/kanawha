#ifndef __KANAWHA__MPAGE_H__
#define __KANAWHA__MPAGE_H__

#include <kanawha/types.h>
#include <kanawha/pointer.h>
#include <kanawha/ops.h>

struct mpage;
struct mpage_ops;

struct mpage {
    void __phys *paddr;
    order_t order;
    struct mpage_ops *ops;
};

#define MPAGE_GET_SIG(RET,ARG,...)\
RET(int)

#define MPAGE_PUT_SIG(RET,ARG,...)\
RET(int)

#define MPAGE_FLUSH_SIG(RET,ARG,...)\
RET(int)

#define MPAGE_MARK_DIRTY (1UL<<0)
#define MPAGE_MARK_SIG(RET,ARG,...)\
RET(int)\
ARG(unsigned long, status)

#define MPAGE_OP_LIST(OP,...)\
OP(flush, MPAGE_FLUSH_SIG, ##__VA_ARGS__)\
OP(get, MPAGE_GET_SIG, ##__VA_ARGS__)\
OP(put, MPAGE_PUT_SIG, ##__VA_ARGS__)\
OP(mark, MPAGE_MARK_SIG, ##__VA_ARGS__)\

struct mpage_ops {
DECLARE_OP_LIST_PTRS(MPAGE_OP_LIST, struct mpage *);
};

DEFINE_OP_LIST_WRAPPERS(
        MPAGE_OP_LIST,
        static inline,
        /* No Prefix */,
        mpage,
        OPS_STRUCT_PTR_ACCESSOR,
        SELF_ACCESSOR
        )

int
mpage_init(
        struct mpage *page,
        void __phys *paddr,
        order_t order,
        struct mpage_ops *ops);
int
mpage_deinit(
        struct mpage *page);

void __phys *
mpage_get_phys(
        struct mpage *);
order_t
mpage_get_order(
        struct mpage *);
size_t
mpage_get_size(
        struct mpage *);

// Default Implementations
int
mpage_nop_flush(
        struct mpage *page);

// Anonymous Pages

// Returns an anonymous mpage of zeros,
// with one reference.
// When all references are "put" the mpage
// will be freed.
struct mpage *
mpage_get_anonymous(
        order_t order);

#endif
