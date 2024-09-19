#ifndef __KANAWHA_DRIVERS__PS2_PORT_H__
#define __KANAWHA_DRIVERS__PS2_PORT_H__

#include <kanawha/ops.h>
#include <kanawha/list.h>
#include <kanawha/spinlock.h>
#include <kanawha/time.h>

struct ps2_port;
struct ps2_port_ops;

typedef void(ps2_recv_callback_f)(
        struct ps2_port *port,
        void *priv_data,
        uint8_t data);

// Should be non-blocking
#define PS2_PORT_SEND_SIG(RET,ARG)\
RET(int)\
ARG(uint8_t, data)

#define PS2_PORT_OP_LIST(OP, ...)\
OP(send, PS2_PORT_SEND_SIG, ##__VA_ARGS__)

struct ps2_port_ops {
DECLARE_OP_LIST_PTRS(PS2_PORT_OP_LIST, struct ps2_port *);
};

struct ps2_port {
    struct ps2_port_ops *ops;

    // If callback is non-NULL then
    // the port needs to invoke "callback"
    // for every byte of data it receives
    // from the device
    void *callback_data;
    ps2_recv_callback_f *callback;

    ilist_node_t global_node;
    ilist_node_t driver_node;

    unsigned has_driver : 1;
};

DEFINE_OP_LIST_WRAPPERS(
        PS2_PORT_OP_LIST,
        static inline,
        /* No Prefix */,
        ps2_port,
        ->ops->,
        SELF_ACCESSOR);

#undef PS2_PORT_SEND_BYTE_SIG
#undef PS2_PORT_RECV_BYTE_SIG
#undef PS2_PORT_OP_LIST

int
ps2_register_port(
        struct ps2_port *port);
int
ps2_unregister_port(
        struct ps2_port *port);

/*
 * API to be used by ps2 drivers
 */

int
ps2_port_set_callback(
        struct ps2_port *port,
        ps2_recv_callback_f *func,
        void *priv_data);

// Issues standard commands to the device,
// forcing it to start/stop sending unsolicited data
//
// Saves and restores "callback/callback_data" internally
int
ps2_port_enable_scanning(
        struct ps2_port *port);
int
ps2_port_disable_scanning(
        struct ps2_port *port);

#endif
