#ifndef __KANAWHA__SH_CMD_H__
#define __KANAWHA__SH_CMD_H__

struct cmd;
struct cmd_invoke;
struct cmd_pipe;

int
cmd_destroy(
        struct cmd *);

struct cmd_invoke *
cmd_invoke_create(
        const char *name,
        unsigned long flags);
int
cmd_invoke_destroy(
        struct cmd_invoke *);
int
cmd_invoke_exec(
        struct cmd_invoke *);
struct cmd *
cmd_invoke_as_cmd(
        struct cmd_invoke *);
struct cmd_invoke *
cmd_as_cmd_invoke(
        struct cmd *);
int
cmd_invoke_push_arg(
        struct cmd_invoke *,
        const char *);

struct cmd_pipe *
cmd_pipe_create(
        struct cmd *from,
        struct cmd *to,
        unsigned long flags);
int
cmd_pipe_destroy(
        struct cmd_pipe *);
int
cmd_pipe_exec(
        struct cmd_pipe *);
struct cmd *
cmd_pipe_as_cmd(
        struct cmd_pipe *);
struct cmd_pipe *
cmd_as_cmd_pipe(
        struct cmd *);

int cmd_exec(struct cmd *);

#endif
