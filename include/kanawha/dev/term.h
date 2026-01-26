#ifndef __KANAWHA__DEV_TERM_H__
#define __KANAWHA__DEV_TERM_H__

#include <kanawha/dev.h>
#include <kanawha/ops.h>
#include <kanawha/lock.h>
#include <kanawha/rwlock.h>
#include <kanawha/waitqueue.h>

struct term_dev;
struct term_driver;

typedef size_t baud_t;

#define TERM_DEV_PUTC_SIG(RET,ARG,...)\
RET(int)\
ARG(char, c)

#define TERM_DEV_FLUSH_SIG(RET,ARG,...)\
RET(int)

#define TERM_DEV_SET_BAUDRATE_SIG(RET,ARG,...)\
RET(int)\
ARG(baud_t, baud)\

#define TERM_DEV_GET_BAUDRATE_SIG(RET,ARG,...)\
RET(int)\
ARG(baud_t *, baud)\

#define TERM_DEV_OP_LIST(OP, ...)\
OP(putc, TERM_DEV_PUTC_SIG, ##__VA_ARGS__)\
OP(flush, TERM_DEV_FLUSH_SIG, ##__VA_ARGS__)\
OP(set_baudrate, TERM_DEV_SET_BAUDRATE_SIG, ##__VA_ARGS__)\
OP(get_baudrate, TERM_DEV_GET_BAUDRATE_SIG, ##__VA_ARGS__)\

struct term_driver {
DECLARE_OP_LIST_PTRS(TERM_DEV_OP_LIST, struct term_dev *);
};

struct term_buffer {
    size_t len;
    char *data;
};

struct term_mode
{
    unsigned long raw : 1; // Do not do line buffering/modification
    unsigned echo     : 1; // Echo output (Depends on NOT raw)

    unsigned input_nl_to_cr : 1; // Translate \n to \r on input
    unsigned input_cr_to_nl : 1; // Translate \r to \n on input
    unsigned input_ign_cr   : 1; // Ignore all \r which are inputted (after xlation)
    unsigned input_ign_nl   : 1; // Ignore all \n which are inputted (after xlation)

    unsigned output_cr_to_nl : 1; // Translate \r to \n on output
    unsigned output_nl_to_cr : 1; // Translate \n to \r on output
    unsigned output_nl_to_crnl : 1; // When outputting \n output \r\n (after xlation)
    unsigned output_cr_to_crnl : 1; // When outputting \r output \r\n (after xlation)

    unsigned input_full_bell : 1; // Output BEL if the input buffer is full
};

struct term_dev {
    struct dev dev;
    struct term_driver *driver;

    struct waitqueue read_wq;
    struct waitqueue write_wq;

    struct rlock mode_lock;
    struct term_mode mode;

    size_t buflen;
    size_t buffer_queue_len;

    irq_lock_t buffer_queue_lock;
    size_t buffer_queue_head;
    size_t buffer_queue_tail;
    struct term_buffer *buffer_queue;

    irq_lock_t buffer_lock;
    size_t raw_head;
    size_t raw_tail;
    size_t canon_input_offset;
    char *input_buffer;
    size_t canon_output_offset;
    char *canon_output_buffer;
    size_t canon_output_buflen;
};

/*
 * Called by terminal devices when
 * they receive an input character
 */
int
term_driver_provide_input(
	struct term_dev *dev,
	char c);

/*
 * Called by the terminal driver
 * when more output can be received
 */
void
term_driver_poke_output(
	struct term_dev *dev);

// Returns
//    positive amount read on success
//    0 if EOF signalled
//    -EWOULDBLOCK if no input is available
//    Other negative errno for misc. errors
ssize_t
term_driver_read_nonblocking(
	struct term_dev *dev,
	void *buffer,
	size_t buflen);

// See comment on "term_driver_read_nonblocking"
ssize_t
term_driver_write_nonblocking(
	struct term_dev *dev,
	void *buffer,
	size_t buflen);

int
term_driver_input_empty(
	struct term_dev *dev);

int
term_driver_output_full(
	struct term_dev *dev);

// Drops all buffered input if changing modes
int
term_driver_set_raw(
	struct term_dev *dev,
	int is_raw);

static inline int
term_driver_enable_raw(struct term_dev *dev)
{
    return term_driver_set_raw(dev, 1);
}
static inline int
term_driver_enable_canonical(struct term_dev *dev)
{
    return term_driver_set_raw(dev, 0);
}

DEFINE_OP_LIST_WRAPPERS(
	TERM_DEV_OP_LIST,
	static inline,
	/* No Prefix */,
	term_dev,
	DRIVER_STRUCT_PTR_ACCESSOR,
	SELF_ACCESSOR);

DECLARE_DEV_TYPE(term_dev);

#undef TERM_DEV_OP_LIST
#undef TERM_DEV_READ_SIG
#undef TERM_DEV_WRITE_SIG
#undef TERM_DEV_SET_BAUDRATE_SIG
#undef TERM_DEV_GET_BAUDRATE_SIG

/*
 * Default Error Implementations
 */

int
term_dev_cannot_get_baudrate(
	struct term_dev *dev,
	baud_t *baud);

int
term_dev_cannot_set_baudrate(
	struct term_dev *dev,
	baud_t baud);

#endif
