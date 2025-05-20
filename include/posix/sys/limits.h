#ifndef __ELK_POSIX__SYS_LIMITS_H__
#define __ELK_POSIX__SYS_LIMITS_H__

#include <limits.h>

//    Maximum number of I/O operations in a single list I/O call supported by the implementation.
//    Minimum Acceptable Value: {_POSIX_AIO_LISTIO_MAX}
//#define AIO_LISTIO_MAX
//    Maximum number of outstanding asynchronous I/O operations supported by the implementation.
//    Minimum Acceptable Value: {_POSIX_AIO_MAX}
//#define AIO_MAX
//    The maximum amount by which a process can decrease its asynchronous I/O priority level from its own scheduling priority.
//    Minimum Acceptable Value: 0
//#define AIO_PRIO_DELTA_MAX
//    Maximum length of argument to the exec functions including environment data.
//    Minimum Acceptable Value: {_POSIX_ARG_MAX}
#define ARG_MAX 4096
//    Maximum number of functions that may be registered with atexit().
//    Minimum Acceptable Value: 32
#define ATEXIT_MAX 32
//    Maximum number of simultaneous processes per real user ID.
//    Minimum Acceptable Value: {_POSIX_CHILD_MAX}
#define CHILD_MAX 4096
//    Maximum number of timer expiration overruns.
//    Minimum Acceptable Value: {_POSIX_DELAYTIMER_MAX}
#define DELAYTIMER_MAX 32
//    Maximum length of a host name (not including the terminating null) as returned from the gethostname() function.
//    Minimum Acceptable Value: {_POSIX_HOST_NAME_MAX}
#define HOST_NAME_MAX 64
//    Maximum number of iovec structures that one process has available for use with readv() or writev().
//    Minimum Acceptable Value: {_XOPEN_IOV_MAX}
//#define IOV_MAX
//    Maximum length of a login name.
//    Minimum Acceptable Value: {_POSIX_LOGIN_NAME_MAX}
#define LOGIN_NAME_MAX 64
//    The maximum number of open message queue descriptors a process may hold.
//    Minimum Acceptable Value: {_POSIX_MQ_OPEN_MAX}
//#define MQ_OPEN_MAX
//    The maximum number of message priorities supported by the implementation.
//    Minimum Acceptable Value: {_POSIX_MQ_PRIO_MAX}
//#define MQ_PRIO_MAX
//    A value one greater than the maximum value that the system may assign to a newly-created file descriptor.
//    Minimum Acceptable Value: {_POSIX_OPEN_MAX}
//#define OPEN_MAX
//    Size in bytes of a page.
//    Minimum Acceptable Value: 1
//#define PAGESIZE
//    Equivalent to {PAGESIZE}. If either {PAGESIZE} or {PAGE_SIZE} is defined, the other is defined with the same value.
//
//#define PAGE_SIZE
//    Maximum number of attempts made to destroy a thread's thread-specific data values on thread exit.
//    Minimum Acceptable Value: {_POSIX_THREAD_DESTRUCTOR_ITERATIONS}
//#define PTHREAD_DESTRUCTOR_ITERATIONS
//    Maximum number of data keys that can be created by a process.
//    Minimum Acceptable Value: {_POSIX_THREAD_KEYS_MAX}
//#define PTHREAD_KEYS_MAX
//    Minimum size in bytes of thread stack storage.
//    Minimum Acceptable Value: 0
//#define PTHREAD_STACK_MIN
//    Maximum number of threads that can be created per process.
//    Minimum Acceptable Value: {_POSIX_THREAD_THREADS_MAX}
//#define PTHREAD_THREADS_MAX
//    Maximum number of realtime signals reserved for application use in this implementation.
//    Minimum Acceptable Value: {_POSIX_RTSIG_MAX}
//#define RTSIG_MAX
//    Maximum number of semaphores that a process may have.
//    Minimum Acceptable Value: {_POSIX_SEM_NSEMS_MAX}
//#define SEM_NSEMS_MAX
//    The maximum value a semaphore may have.
//    Minimum Acceptable Value: {_POSIX_SEM_VALUE_MAX}
//#define SEM_VALUE_MAX
//    Maximum number of queued signals that a process may send and have pending at the receiver(s) at any time.
//    Minimum Acceptable Value: {_POSIX_SIGQUEUE_MAX}
//#define SIGQUEUE_MAX
//    The maximum number of replenishment operations that may be simultaneously pending for a particular sporadic server scheduler.
//    Minimum Acceptable Value: {_POSIX_SS_REPL_MAX}
//#define SS_REPL_MAX
//    Maximum number of streams that one process can have open at one time. If defined, it has the same value as {FOPEN_MAX} (see <stdio.h>).
//    Minimum Acceptable Value: {_POSIX_STREAM_MAX}
//#define STREAM_MAX
//    Maximum number of symbolic links that can be reliably traversed in the resolution of a pathname in the absence of a loop.
//    Minimum Acceptable Value: {_POSIX_SYMLOOP_MAX}
//#define SYMLOOP_MAX
//    Maximum number of timers per process supported by the implementation.
//    Minimum Acceptable Value: {_POSIX_TIMER_MAX}
//#define TIMER_MAX
//    Maximum length of the trace event name (not including the terminating null).
//    Minimum Acceptable Value: {_POSIX_TRACE_EVENT_NAME_MAX}
#define TRACE_EVENT_NAME_MAX 64
//    Maximum length of the trace generation version string or of the trace stream name (not including the terminating null).
//    Minimum Acceptable Value: {_POSIX_TRACE_NAME_MAX}
#define TRACE_NAME_MAX 64
//    Maximum number of trace streams that may simultaneously exist in the system.
//    Minimum Acceptable Value: {_POSIX_TRACE_SYS_MAX}
//#define TRACE_SYS_MAX
//    Maximum number of user trace event type identifiers that may simultaneously exist in a traced process, including the predefined user trace event POSIX_TRACE_UNNAMED_USER_EVENT.
//    Minimum Acceptable Value: {_POSIX_TRACE_USER_EVENT_MAX}
//#define TRACE_USER_EVENT_MAX
//    Maximum length of terminal device name.
//    Minimum Acceptable Value: {_POSIX_TTY_NAME_MAX}
//#define TTY_NAME_MAX
//    Maximum number of bytes supported for the name of a timezone (not of the TZ variable).
//    Minimum Acceptable Value: {_POSIX_TZNAME_MAX} 
//#define TZNAME_MAX


// Runtime Values

//    Minimum number of bits needed to represent, as a signed integer value, the maximum size of a regular file allowed in the specified directory.
//    Minimum Acceptable Value: 32
//#define FILESIZEBITS
//    Maximum number of links to a single file.
//    Minimum Acceptable Value: {_POSIX_LINK_MAX}
//#define LINK_MAX
//    Maximum number of bytes in a terminal canonical input line.
//    Minimum Acceptable Value: {_POSIX_MAX_CANON}
//#define MAX_CANON
//    Minimum number of bytes for which space is available in a terminal input queue; therefore, the maximum number of bytes a conforming application may require to be typed as input before reading them.
//    Minimum Acceptable Value: {_POSIX_MAX_INPUT}
//#define MAX_INPUT
//    Maximum number of bytes in a filename (not including the terminating null of a filename string).
//    Minimum Acceptable Value: {_POSIX_NAME_MAX}
#define NAME_MAX 128
//    Maximum number of bytes the implementation will store as a pathname in a user-supplied buffer of unspecified size, including the terminating null character. Minimum number the implementation will accept as the maximum number of bytes in a pathname.
//    Minimum Acceptable Value: {_POSIX_PATH_MAX}
#define PATH_MAX 256
//    Maximum number of bytes that is guaranteed to be atomic when writing to a pipe.
//    Minimum Acceptable Value: {_POSIX_PIPE_BUF}
#define PIPE_BUF 512
//    Minimum number of bytes of storage actually allocated for any portion of a file.
//    Minimum Acceptable Value: Not specified.
//#define POSIX_ALLOC_SIZE_MIN
//    Recommended increment for file transfer sizes between the {POSIX_REC_MIN_XFER_SIZE} and {POSIX_REC_MAX_XFER_SIZE} values.
//    Minimum Acceptable Value: Not specified.
//#define POSIX_REC_INCR_XFER_SIZE
//    Maximum recommended file transfer size.
//    Minimum Acceptable Value: Not specified.
//#define POSIX_REC_MAX_XFER_SIZE
//    Minimum recommended file transfer size.
//    Minimum Acceptable Value: Not specified.
//#define POSIX_REC_MIN_XFER_SIZE
//    Recommended file transfer buffer alignment.
//    Minimum Acceptable Value: Not specified.
//#define POSIX_REC_XFER_ALIGN
//    Maximum number of bytes in a symbolic link.
//    Minimum Acceptable Value: {_POSIX_SYMLINK_MAX} 
#define SYMLINK_MAX 256

#endif
