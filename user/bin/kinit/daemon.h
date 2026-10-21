#ifndef __KINIT__DAEMON_H__
#define __KINIT__DAEMON_H__

struct kinit_daemon;

typedef enum kinit_daemon_status {
    KINIT_DAEMON_STATUS_STOPPED = 0,
    KINIT_DAEMON_STATUS_STARTING,
    KINIT_DAEMON_STATUS_RUNNING,
    KINIT_DAEMON_STATUS_EXITED,
    KINIT_DAEMON_STATUS_STOPPING,
} kinit_daemon_status_t;

int
kinit_setup_daemons(void);
int
kinit_cleanup_daemons(void);

struct kinit_daemon *
kinit_create_daemon(void);

int
kinit_daemon_set_name(
        struct kinit_daemon *,
        const char *);
const char *
kinit_daemon_get_name(
        struct kinit_daemon *);

struct kinit_daemon *
kinit_daemons_begin(void);
struct kinit_daemon *
kinit_daemons_next(
        struct kinit_daemon *iter);

int
kinit_daemon_set_exec_command(
        struct kinit_daemon *daemon,
        const char **command,
        unsigned long len);

const char **
kinit_daemon_get_exec_command(
        struct kinit_daemon *daemon);

int
kinit_daemon_start_manager(
        struct kinit_daemon *d);
int
kinit_daemon_stop_manager(
        struct kinit_daemon *d);

int
kinit_daemon_add_socket(
        struct kinit_daemon *d,
        const char *env);

#endif
