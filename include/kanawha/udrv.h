#ifndef __KANAWHA__UDRV_H__
#define __KANAWHA__UDRV_H__

#include <kanawha/ops.h>
#include <kanawha/registry.h>
#include <kanawha/waitqueue.h>
#include <kanawha/sysfs/vfs.h>
#include <kanawha/sysfs/sysfs.h>
#include <kanawha/uapi/udrv.h>

struct udrv_mount;
struct udrv_dev;

#define UDRV_CREATE_SIG(RET,ARG,...)\
RET(struct udrv_dev *)\
ARG(const char *, name)\

#define UDRV_DESTROY_SIG(RET,ARG,...)\
RET(int)\
ARG(struct udrv_dev *, dev)

#define UDRV_ON_RECV_SIG(RET,ARG,...)\
RET(int)\
ARG(struct udrv_dev *, dev)\
ARG(struct udrv_pkt *, pkt)\
ARG(size_t, pktlen)\

#define UDRV_MOUNT_OP_LIST(OP,...)\
OP(create,  UDRV_CREATE_SIG,  ##__VA_ARGS__)\
OP(destroy, UDRV_DESTROY_SIG, ##__VA_ARGS__)\
OP(on_recv, UDRV_ON_RECV_SIG, ##__VA_ARGS__)\

struct udrv_mount_ops {
DECLARE_OP_LIST_PTRS(UDRV_MOUNT_OP_LIST, struct udrv_mount *);
};

struct udrv_mount {
    struct udrv_mount_ops *ops;

    struct registry_node registry_node;
    struct vfs_node vfs_node;
};

DEFINE_OP_LIST_WRAPPERS(
	UDRV_MOUNT_OP_LIST,
	static inline,
	/* No Prefix */,
	udrv_mount,
	OPS_STRUCT_PTR_ACCESSOR,
	SELF_ACCESSOR);

DECLARE_REGISTRY(udrv_mount);

struct udrv_dev
{
    struct udrv_mount *mnt;
    struct vfs_node vfs_node;

    struct waitqueue write_wq;
    struct waitqueue read_wq;
    struct waitqueue send_wq;

    irq_lock_t read_pkt_queue_lock;
    ilist_t read_pkt_queue;
    unsigned long read_pkts_queued;
    unsigned long max_read_pkts_queued;
};

static inline void
udrv_dev_wake_writers(
	struct udrv_dev *dev)
{
    wake_all(&dev->write_wq);
}
static inline void
udrv_dev_wake_readers(
	struct udrv_dev *dev)
{
    wake_all(&dev->read_wq);
}

// This is a packet destined for userspace
struct udrv_pkt *
udrv_create_user_pkt(
	size_t pktlen);

// This will invalidate the packet pointer
// (Frees the backing memory when the packet is fully sent)
int
udrv_send_user_pkt(
	struct udrv_dev *dev,
	struct udrv_pkt *pkt);

// This will ignore buffer length and force a packet to
// be send regardless of how many packets are currently queued
// for userspace (should only be used in rare circumstances)
int
udrv_send_user_pkt_no_wait(
	struct udrv_dev *dev,
	struct udrv_pkt *pkt);

// This destroys the packet without sending it
int
udrv_drop_user_pkt(
	struct udrv_dev *dev,
	struct udrv_pkt *pkt);

#endif
