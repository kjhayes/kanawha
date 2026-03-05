#ifndef __KANAWHA__USB_XHCI_TRB_H__
#define __KANAWHA__USB_XHCI_TRB_H__

#include <kanawha/attribute.h>
#include <kanawha/endian.h>
#include <stdint.h>

#define USB_XHCI_TRB_COMPLETION_CODE_XLIST(X)                                  \
    X(INVALID, (0))                                                            \
    X(SUCCESS, (1))                                                            \
    X(DATA_BUFFER_ERROR, (2))                                                  \
    X(BABBLE_DETECTED_ERROR, (3))                                              \
    X(USB_TRANSACTION_ERROR, (4))                                              \
    X(TRB_ERROR, (5))                                                          \
    X(STALL_ERROR, (6))                                                        \
    X(RESOURCE_ERROR, (7))                                                     \
    X(BANDWIDTH_ERROR, (8))                                                    \
    X(NO_SLOTS_AVAILABLE_ERROR, (9))                                           \
    X(INVALID_STREAM_TYPE_ERROR, (10))                                         \
    X(SLOT_NOT_ENABLED_ERROR, (11))                                            \
    X(ENDPOINT_NOT_ENABLED_ERROR, (12))                                        \
    X(SHORT_PACKET, (13))                                                      \
    X(RING_UNDERRUN, (14))                                                     \
    X(RING_OVERRUN, (15))                                                      \
    X(VF_EVENT_RING_FULL_ERROR, (16))                                          \
    X(PARAMETER_ERROR, (17))                                                   \
    X(BANDWIDTH_OVERRUN_ERROR, (18))                                           \
    X(CONTEXT_STATE_ERROR, (19))                                               \
    X(NO_PING_RESPONSE_ERROR, (20))                                            \
    X(EVENT_RING_FULL_ERROR, (21))                                             \
    X(INCOMPATIBLE_DEVICE_ERROR, (22))                                         \
    X(MISSED_SERIVCE_ERROR, (23))                                              \
    X(COMMAND_RING_STOPPED, (24))                                              \
    X(COMMAND_ABORTED, (25))                                                   \
    X(STOPPED, (26))                                                           \
    X(STOPPED_LENGTH_INVALID, (27))                                            \
    X(STOPPED_SHORT_PACKET, (28))                                              \
    X(MAX_EXIT_LATENCY_TOO_LARGE_ERROR, (29))                                  \
    X(ISOCH_BUFFER_OVERRUN, (31))                                              \
    X(EVENT_LOST_ERROR, (32))                                                  \
    X(UNDEFINED_ERROR, (33))                                                   \
    X(INVALID_STREAM_ID_ERROR, (34))                                           \
    X(SECONDARY_BANDWIDTH_ERROR, (35))                                         \
    X(SPLIT_TRANSACTION_ERROR, (36))

#define __DEFINE_CONST(__NAME, __VAL)                                          \
    const static unsigned int USB_XHCI_TRB_COMPLETION_CODE_##__NAME = __VAL;
USB_XHCI_TRB_COMPLETION_CODE_XLIST(__DEFINE_CONST)
#undef __DEFINE_CONST

#define USB_XHCI_TRB_TYPE_XLIST(X)                                             \
    X(NORMAL, (1))                                                             \
    X(SETUP_STAGE, (2))                                                        \
    X(DATA_STAGE, (3))                                                         \
    X(STATUS_STAGE, (4))                                                       \
    X(ISOCH, (5))                                                              \
    X(LINK, (6))                                                               \
    X(EVENT_DATA, (7))                                                         \
    X(NOOP, (8))                                                               \
    X(ENABLE_SLOT_CMD, (9))                                                    \
    X(DISABLE_SLOT_CMD, (10))                                                  \
    X(ADDR_DEVICE_CMD, (11))                                                   \
    X(CONFIGURE_ENDPOINT_CMD, (12))                                            \
    X(EVAL_CTX_CMD, (13))                                                      \
    X(RESET_ENDPOINT_CMD, (14))                                                \
    X(STOP_ENDPOINT_CMD, (15))                                                 \
    X(SET_TR_DEQUEUE_CMD, (16))                                                \
    X(RESET_DEVICE_CMD, (17))                                                  \
    X(FORCE_EVENT_CMD, (18))                                                   \
    X(NEGOTIATE_BANDWIDTH_CMD, (19))                                           \
    X(SET_LATENCY_TOLERANCE_CMD, (20))                                         \
    X(GET_PORT_BANDWIDTH_CMD, (21))                                            \
    X(FORCE_HEADER_CMD, (22))                                                  \
    X(NOOP_CMD, (23))                                                          \
    X(GET_EXT_PROPERTY_CMD, (24))                                              \
    X(SET_EXT_PROPERTY_CMD, (25))                                              \
    X(TRANSFER_EVENT, (32))                                                    \
    X(COMMAND_COMPLETION_EVENT, (33))                                          \
    X(PORT_STATUS_CHANGE_EVENT, (34))                                          \
    X(BANDWIDTH_REQUEST_EVENT, (35))                                           \
    X(DOORBELL_EVENT, (36))                                                    \
    X(HOST_CONTROLLER_EVENT, (37))                                             \
    X(DEVICE_NOTIFICATION_EVENT, (38))                                         \
    X(MFINDEX_WRAP_EVENT, (39))

#define __DEFINE_CONST(__NAME, __VAL)                                          \
    const static unsigned int USB_XHCI_TRB_TYPE_##__NAME = __VAL;
USB_XHCI_TRB_TYPE_XLIST(__DEFINE_CONST)
#undef __DEFINE_CONST

struct __packed usb_xhci_trb
{
    le64_t param;
    le32_t status;
    le32_t control;
};
ASSERT_TYPE_SIZE(struct usb_xhci_trb, 16);

int
usb_xhci_trb_get_cycle(struct usb_xhci_trb *trb);
void
usb_xhci_trb_set_cycle(struct usb_xhci_trb *trb, int value);
void
usb_xhci_trb_toggle_cycle(struct usb_xhci_trb *trb, int value);
uint8_t
usb_xhci_trb_get_type(struct usb_xhci_trb *trb);
void
usb_xhci_trb_set_type(struct usb_xhci_trb *trb, uint8_t value);

int
usb_xhci_trb_completion_code_is_success(uint8_t value);

const char *
usb_xhci_trb_completion_code_to_string(uint8_t cc);

const char *
usb_xhci_trb_type_to_string(uint8_t type);

#ifndef KEEP_USB_XHCI_TRB_COMPLETION_CODE_XLIST
#undef USB_XHCI_TRB_COMPLETION_CODE_XLIST
#endif
#ifndef KEEP_USB_XHCI_TRB_TYPE_XLIST
#undef USB_XHCI_TRB_TYPE_XLIST
#endif

static inline int
usb_xhci_dump_trb(printk_f *printer, struct usb_xhci_trb *trb)
{
    uint8_t type = usb_xhci_trb_get_type(trb);
    (*printer)("{type=%s,param=0x%lx,status=0x%lx,control=0x%lx}",
               usb_xhci_trb_type_to_string(type),
               letoh64(trb->param),
               letoh32(trb->status),
               letoh32(trb->control));
    return 0;
}

#endif
