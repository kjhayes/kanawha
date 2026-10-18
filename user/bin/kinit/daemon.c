
#include "daemon.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <threads.h>
#include <unistd.h>
#include <sys/wait.h>
#include <elk/list.h>

typedef enum kinit_daemon_manager_status {
    KINIT_DAEMON_MANAGER_STATUS_INIT = 0,
    KINIT_DAEMON_MANAGER_STATUS_MANAGED,
    KINIT_DAEMON_MANAGER_STATUS_STOPPING,
    KINIT_DAEMON_MANAGER_STATUS_UNMANAGED,
} kinit_daemon_manager_status_t;

struct kinit_daemon
{
    kinit_daemon_manager_status_t manager_status;
    kinit_daemon_status_t status;

    char *name;
    char **exec_command;

    thrd_t manager;
    int pid;

    list_node_t list_node;
};

static list_t daemon_list;

int
kinit_setup_daemons(void)
{
    list_init(&daemon_list);
}

int
kinit_cleanup_daemons(void)
{
    list_node_t *iter;
    while(1) {
        list_node_t *list_node;
        list_node = list_begin(&daemon_list);
        if(list_node == NULL) {
            break;
        }
        struct kinit_daemon *d;
        d = container_of(list_node, struct kinit_daemon, list_node);
        // TODO Mark the daemon for destruction
        // kinit_destroy_daemon(d);
    }
    return 0;
}

static void
kinit_destroy_daemon_from_manager(
        struct kinit_daemon *d)
{
    list_remove(&daemon_list, &d->list_node);
    {
        char **iter = d->exec_command;
        while(*iter) {
            free(*iter);
            iter++;
        }
        free(d->exec_command);
        d->exec_command = NULL;
    }
    free(d->name);
    free(d);
}

static void
kinit_daemon_manager_tick_running(
        struct kinit_daemon *d)
{
    int res;
    int stat;
    res = waitpid(d->pid, &stat, 0);
    if(res < 0) {
        fprintf(stderr, "kinit: daemon manager waitpid returned \"%s\"\n",
                strerror(d->pid));
        return;
    }
    if(res == d->pid) {
        d->status = KINIT_DAEMON_STATUS_EXITED;
        d->pid = -1;
    }
}

static void
kinit_daemon_manager_tick_starting(
        struct kinit_daemon *d)
{
    if(d->exec_command == NULL) {
        fprintf(stderr, "kinit: cannot start daemon without exec command!\n");
        return;
    }

    int fork_pid = fork();
    if(fork_pid < 0) {
        fprintf(stderr, "kinit: failed to fork daemon!\n");
        return;
    }
    if(fork_pid == 0) {
        // We are the child
        char **exec = d->exec_command;
        execvp(exec[0], exec);
        perror("execvp");
        exit(-1);
    }

    d->pid = fork_pid;
    d->status = KINIT_DAEMON_STATUS_RUNNING;

    return;
}

static void
kinit_daemon_manager_tick_stopping(
        struct kinit_daemon *d)
{
    // TODO
}

static void
kinit_daemon_manager_tick_stopped(
        struct kinit_daemon *d)
{
    // TODO
}

static void
kinit_daemon_manager_tick_exited(
        struct kinit_daemon *d)
{
    // TODO: diffrentiate between daemons which
    // should auto-restart vs. stay exited until
    // manually started again.
    d->status = KINIT_DAEMON_STATUS_STARTING;
}

static void
kinit_daemon_manager_tick(
        struct kinit_daemon *d)
{
    switch(d->status) {
        case KINIT_DAEMON_STATUS_EXITED:
            kinit_daemon_manager_tick_exited(d);
            break;
        case KINIT_DAEMON_STATUS_STARTING:
            kinit_daemon_manager_tick_starting(d);
            break;
        case KINIT_DAEMON_STATUS_RUNNING:
            kinit_daemon_manager_tick_running(d);
            break;
        case KINIT_DAEMON_STATUS_STOPPING:
            kinit_daemon_manager_tick_stopping(d);
            break;
        case KINIT_DAEMON_STATUS_STOPPED:
            kinit_daemon_manager_tick_stopped(d);
            break;
    }
}

static int
kinit_daemon_manager(void *_d)
{
    struct kinit_daemon *d = _d;

    while(d->manager_status == KINIT_DAEMON_MANAGER_STATUS_MANAGED)
    {
        kinit_daemon_manager_tick(d);
    }

    if(d->manager_status != KINIT_DAEMON_MANAGER_STATUS_STOPPING) {
        fprintf(stderr, "kinit: daemon was not marked as stopping on manager exit!\n");
        return -EINVAL;
    }
    d->manager_status = KINIT_DAEMON_MANAGER_STATUS_UNMANAGED;

    kinit_destroy_daemon_from_manager(d);
    return 0;
}

struct kinit_daemon *
kinit_create_daemon(void)
{
    int res;

    struct kinit_daemon *d = malloc(sizeof(*d));
    if(d == NULL) {
        return NULL;
    }
    d->name = NULL;
    d->exec_command = NULL;
    d->pid = -1;
    d->status = KINIT_DAEMON_STATUS_EXITED;
    d->manager_status = KINIT_DAEMON_MANAGER_STATUS_INIT;

    list_push_tail(&daemon_list, &d->list_node);

    return d;
}

int
kinit_daemon_set_name(
        struct kinit_daemon *d,
        const char *name)
{
    char *old = d->name;
    char *new = strdup(name);
    if(new == NULL) {
        return -ENOMEM;
    }
    d->name = new;
    free(old);
    return 0;
}

const char *
kinit_daemon_get_name(
        struct kinit_daemon *d)
{
    if(d->name == NULL) {
        return "";
    }
    return d->name;
}

int
kinit_daemon_set_exec_command(
        struct kinit_daemon *d,
        const char **command,
        unsigned long len)
{
    char **buffer = calloc(sizeof(const char **), len+1);
    if(buffer == NULL) {
        return -ENOMEM;
    }

    for(unsigned long i = 0; i < len; i++) {
        char *dup = strdup(command[i]);
        if(dup == NULL) {
            for(unsigned long j = 0; j < i; j++) {
                free(buffer[j]);
                free(buffer);
                return -ENOMEM;
            }
        }
        buffer[i] = dup;
    }
    buffer[len] = NULL;

    if(d->exec_command) {
        char **iter = d->exec_command;
        while(*iter) {
            free(*iter);
            iter++;
        }
        free(d->exec_command);
        d->exec_command = NULL;
    }
    d->exec_command = buffer;

    return 0;
}

const char **
kinit_daemon_get_exec_command(
        struct kinit_daemon *d)
{
    static const char *empty_command[] = {
        NULL
    };
    if(d->exec_command == NULL) {
        return (const char **)empty_command;
    }
    return (const char **)d->exec_command;
}

int
kinit_daemon_start_manager(
        struct kinit_daemon *d)
{
    int res;
    if(d->manager_status != KINIT_DAEMON_MANAGER_STATUS_INIT) {
        fprintf(stderr, "kinit_daemon_start_manager: manager_status != INIT\n");
        return -EINVAL;
    }
    d->manager_status = KINIT_DAEMON_MANAGER_STATUS_MANAGED;
    res = thrd_create(&d->manager, kinit_daemon_manager, d);
    if(res) {
        fprintf(stderr, "kinit_daemon_start_manager: thrd_create failed!\n");
        return res;
    }
    return 0;
}
int
kinit_daemon_stop_manager(
        struct kinit_daemon *d)
{
    int res;
    if(d->manager_status != KINIT_DAEMON_MANAGER_STATUS_MANAGED) {
        return -EINVAL;
    }
    d->manager_status = KINIT_DAEMON_MANAGER_STATUS_STOPPING;
    int exitcode;
    res = thrd_join(d->manager, &exitcode);
    if(res) {
        return res;
    }
    return exitcode;
}

struct kinit_daemon *
kinit_daemons_begin(void)
{
    list_node_t *iter = list_begin(&daemon_list);
    if(iter == NULL) {
        return NULL;
    }
    return container_of(iter, struct kinit_daemon, list_node);
}

struct kinit_daemon *
kinit_daemons_next(
        struct kinit_daemon *iter)
{
    list_node_t *node = &iter->list_node;
    node = list_next(&daemon_list, node);
    if(node == NULL) {
        return NULL;
    }
    return container_of(node, struct kinit_daemon, list_node);
}

