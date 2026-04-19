#ifndef __KANAWHA__SCSI_SCSI_H__
#define __KANAWHA__SCSI_SCSI_H__

#include <kanawha/ops.h>
#include <kanawha/ptree.h>
#include <kanawha/dev/blk.h>

struct scsi_command {
    enum {
        SCSI_COMMAND_IDLE,
        SCSI_COMMAND_LAUNCHED,
        SCSI_COMMAND_COMPLETED,
    } status;

    enum {
        SCSI_ERROR_NONE = 0,
        SCSI_ERROR_UNKNOWN,
    } error;
};

struct scsi_adaptor;

struct scsi_target {
    uint64_t target;
    uint64_t lun;
};

#define SCSI_CREATE_COMMAND_TARGET_REPORT_LUNS (1UL<<0)
#define SCSI_ADAPTOR_CREATE_COMMAND_SIG(RET,ARG,...)\
RET(struct scsi_command *)\
ARG(struct scsi_target, target)\
ARG(unsigned long, flags)

#define SCSI_ADAPTOR_WRITE_CDB_SIG(RET,ARG,...)\
RET(int)\
ARG(struct scsi_command *, cmd)\
ARG(void *, cdb)\
ARG(size_t, cdb_len)

#define SCSI_ADAPTOR_POINT_IN_DATA_SIG(RET,ARG,...)\
RET(int)\
ARG(struct scsi_command *, cmd)\
ARG(void __phys *, in_data_ptr)\
ARG(size_t, in_data_len)

#define SCSI_ADAPTOR_POINT_OUT_DATA_SIG(RET,ARG,...)\
RET(int)\
ARG(struct scsi_command *, cmd)\
ARG(void __phys *, out_data_ptr)\
ARG(size_t, out_data_len)

#define SCSI_ADAPTOR_LAUNCH_COMMAND_SIG(RET,ARG,...)\
RET(int)\
ARG(struct scsi_command *, cmd)

#define SCSI_ADAPTOR_AWAIT_COMMAND_SIG(RET,ARG,...)\
RET(int)\
ARG(struct scsi_command *, cmd)

#define SCSI_ADAPTOR_DESTROY_COMMAND_SIG(RET,ARG,...)\
RET(int)\
ARG(struct scsi_command *, cmd)

#define SCSI_ADAPTOR_OP_LIST(OP,...)\
OP(create_command, SCSI_ADAPTOR_CREATE_COMMAND_SIG, ##__VA_ARGS__)\
OP(write_cdb, SCSI_ADAPTOR_WRITE_CDB_SIG, ##__VA_ARGS__)\
OP(point_out_data, SCSI_ADAPTOR_POINT_OUT_DATA_SIG, ##__VA_ARGS__)\
OP(point_in_data, SCSI_ADAPTOR_POINT_IN_DATA_SIG, ##__VA_ARGS__)\
OP(launch_command, SCSI_ADAPTOR_LAUNCH_COMMAND_SIG, ##__VA_ARGS__)\
OP(await_command, SCSI_ADAPTOR_AWAIT_COMMAND_SIG, ##__VA_ARGS__)\
OP(destroy_command, SCSI_ADAPTOR_DESTROY_COMMAND_SIG, ##__VA_ARGS__)

struct scsi_adaptor_ops {
    DECLARE_OP_LIST_PTRS(SCSI_ADAPTOR_OP_LIST, struct scsi_adaptor *);
};

struct scsi_adaptor
{
    struct scsi_adaptor_ops *ops;

    struct ptree_node ptree_node;

    // Hints provided by the adaptor driver
    // about how many devices to scan for
    uint64_t max_target;
    uint64_t max_lun;

    struct ptree device_tree;
};

DEFINE_OP_LIST_WRAPPERS(
        SCSI_ADAPTOR_OP_LIST,
        static inline,
        /* No Prefix */,
        scsi_adaptor,
        OPS_STRUCT_PTR_ACCESSOR,
        SELF_ACCESSOR)

int register_scsi_adaptor(struct scsi_adaptor *);
int unregister_scsi_adaptor(struct scsi_adaptor *);

int
scsi_adaptor_run_virtual_command(
        struct scsi_adaptor *adaptor,
        struct scsi_target target,
        void *cdb,
        size_t cdb_len,
        void *from_dev_buffer,
        size_t from_dev_buffer_len,
        void *to_dev_buffer,
        size_t to_dev_buffer_len);

int
scsi_adaptor_run_physical_command(
        struct scsi_adaptor *adaptor,
        struct scsi_target target,
        void *cdb,
        size_t cdb_len,
        void __phys *from_dev_buffer,
        size_t from_dev_buffer_len,
        void __phys *to_dev_buffer,
        size_t to_dev_buffer_len);

// A SCSI Device and Associated Target/LUN
struct scsi_dev
{
    struct scsi_adaptor *adaptor;
    struct scsi_target target;

    size_t lba_count;
    order_t lba_order;

    struct blk_dev blk_dev;

    char *name;

    struct ptree_node adaptor_node;
};

int scsi_dev_init(struct scsi_adaptor *adaptor,
                  struct scsi_dev *dev,
                  struct scsi_target target);
int scsi_dev_deinit(struct scsi_dev *dev);

#endif
