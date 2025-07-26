#ifndef __KANAWHA__REF_H__
#define __KANAWHA__REF_H__

#include <kanawha/ops.h>
#include <kanawha/atomic.h>

struct refobj;

#define REFOBJ_RELEASE_SIG(RET,ARG)\
RET(int)

#define REFOBJ_OPS_LIST(OP, ...)\
OP(release, REFOBJ_RELEASE_SIG, ##__VA_ARGS__)

struct refobj_ops {
DECLARE_OP_LIST_PTRS(REFOBJ_OPS_LIST, struct refobj *);
};

struct refobj
{
    atomic_t refcount;
    struct refobj_ops *ops;
};

int
refobj_init(
	struct refobj *obj,
	struct refobj_ops *ops);

void
refobj_put(
	struct refobj *obj);
void
refobj_get(
	struct refobj *obj);

#endif
