
#include <elk/list.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>

struct cmd
{
    enum {
        CMD_TYPE_INVOKE,
        CMD_TYPE_PIPE,
    } type;
};

struct cmd_invoke_arg {
    list_node_t invoke_node;
    char *value;
};

struct cmd_invoke
{
    struct cmd cmd;
    char *name;
    list_t args;
    unsigned long flags;
};

#undef CMD_INVOKE_XLIST

DEFINE_CUSTOM_LIST(
        cmd_invoke_args,
        struct cmd_invoke,
        args,
        struct cmd_invoke_arg,
        invoke_node);

struct cmd_pipe
{
    struct cmd cmd;
    struct cmd *from;
    struct cmd *to;
    unsigned long flags;
};

static inline int
cmd_init(struct cmd *cmd)
{
    return 0;
}

static inline int
cmd_deinit(struct cmd *cmd)
{
    return 0;
}

struct cmd_invoke *
cmd_invoke_create(
        const char *name,
        unsigned long flags)
{
    int res;
    struct cmd_invoke *i = malloc(sizeof(*i));
    if(i == NULL) {
        return NULL;
    }
    i->flags = flags;
    cmd_invoke_args_init(i);
    i->name = strdup(name);
    if(i->name == NULL) {
        free(i);
        return NULL;
    }
    i->cmd.type = CMD_TYPE_INVOKE;
    res = cmd_init(&i->cmd);
    if(res) {
        free(i->name);
        free(i);
        return NULL;
    }
    return i;
}
int
cmd_invoke_destroy(
        struct cmd_invoke *i)
{
    while(1) {
        struct cmd_invoke_arg *a = cmd_invoke_args_begin(i);
        if(a == NULL) {
            break;
        }
        cmd_invoke_args_remove(i,a);
        free(a->value);
        free(a);
    }
    free(i->name);
    free(i);
    return 0;
}

static int
cmd_invoke_exec_cd(
        struct cmd_invoke *i)
{
    int res;
    if(cmd_invoke_args_count(i) != 1) {
        return -EINVAL;
    }
    struct cmd_invoke_arg *arg = cmd_invoke_args_begin(i);
    if(arg == NULL) {
        return -EINVAL;
    }
    const char *path = arg->value;
    res = chdir(path);
    if(res) {
        fprintf(stderr, "cd: failed with errno=%s\n",
                strerror(errno));
        return res;
    }
    return 0;
}

static int
cmd_invoke_exec_exec(
        struct cmd_invoke *i)
{
    int argc = cmd_invoke_args_count(i);

    char *argv[argc+1];

    int argi = 0;
    struct cmd_invoke_arg *arg = cmd_invoke_args_begin(i);
    while(arg) {
        argv[argi] = arg->value;
        argi++;
        arg = cmd_invoke_args_next(i, arg);
    }
    if(argi != argc) {
        return -EINVAL;
    }
    argv[argc] = NULL;

    exit(execvp(argv[0], argv));

    return -EINVAL;
}

static int
cmd_invoke_exec_file(
        struct cmd_invoke *i)
{
    int res;

    int pid = fork();
    if(pid == 0) {
        int argc = cmd_invoke_args_count(i) + 1;

        char *argv[argc+1];
        argv[0] = i->name;

        int argi = 1;
        struct cmd_invoke_arg *arg = cmd_invoke_args_begin(i);
        while(arg) {
            argv[argi] = arg->value;
            argi++;
            arg = cmd_invoke_args_next(i, arg);
        }
        if(argi != argc) {
            return -EINVAL;
        }
        argv[argc] = NULL;

        exit(execvp(i->name, argv));
    }

    int ret;
    while(waitpid(pid, &ret, 0) != pid) {
        // Spinning...
    }

    return ret;
}

int
cmd_invoke_exec(
        struct cmd_invoke *i)
{
    if(strcmp(i->name, "cd") == 0) {
        return cmd_invoke_exec_cd(i);
    } else if(strcmp(i->name, "exec") == 0) {
        return cmd_invoke_exec_exec(i);
    } else {
        return cmd_invoke_exec_file(i);
    }
}

struct cmd *
cmd_invoke_as_cmd(
        struct cmd_invoke *i)
{
    if(i == NULL) {
        return NULL;
    }
    return &i->cmd;
}
struct cmd_invoke *
cmd_as_cmd_invoke(
        struct cmd *c)
{
    if(c == NULL) {
        return NULL;
    }
    if(c->type != CMD_TYPE_INVOKE) {
        return NULL;
    }
    return container_of(c, struct cmd_invoke, cmd);
}
int
cmd_invoke_push_arg(
        struct cmd_invoke *i,
        const char *av)
{
    struct cmd_invoke_arg *a = malloc(sizeof(*a));
    if(a == NULL) {
        return -ENOMEM;
    }
    a->value = strdup(av);
    if(a->value == NULL) {
        free(a);
        return -ENOMEM;
    }
    cmd_invoke_args_push_tail(i, a);
    return 0;
}

struct cmd_pipe *
cmd_pipe_create(
        struct cmd *from,
        struct cmd *to,
        unsigned long flags)
{
    struct cmd_pipe *p = malloc(sizeof(*p));
    if(p == NULL) {
        return NULL;
    }
    p->flags = flags;
    p->from = from;
    p->to = to;
    return p;
}
int
cmd_pipe_destroy(
        struct cmd_pipe *p)
{
    return 0;
}
int
cmd_pipe_exec(
        struct cmd_pipe *p)
{
    // TODO
    abort();
    return 0;
}
struct cmd *
cmd_pipe_as_cmd(
        struct cmd_pipe *p)
{
    return &p->cmd;
}
struct cmd_pipe *
cmd_as_cmd_pipe(
        struct cmd *c)
{
    return container_of(c, struct cmd_pipe, cmd);
}

int
cmd_destroy(
        struct cmd *c)
{
    cmd_deinit(c);
    switch(c->type) {
        case CMD_TYPE_INVOKE:
            return cmd_invoke_destroy(cmd_as_cmd_invoke(c));
        case CMD_TYPE_PIPE:
            return cmd_pipe_destroy(cmd_as_cmd_pipe(c));
    }
    return -EINVAL;
}

int
cmd_exec(struct cmd *c)
{
    switch(c->type) {
        case CMD_TYPE_INVOKE:
            return cmd_invoke_exec(cmd_as_cmd_invoke(c));
        case CMD_TYPE_PIPE:
            return cmd_pipe_exec(cmd_as_cmd_pipe(c));
    }
    return -EINVAL;
}

