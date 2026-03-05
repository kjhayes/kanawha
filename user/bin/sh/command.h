#ifndef __CABIN_SH__COMMAND_H__
#define __CABIN_SH__COMMAND_H__

#define CONFIG_X64
#include <kanawha/file.h>
#include <kanawha/process.h>

struct cmd_arg
{
    struct cmd_arg *next;
    struct cmd_arg *prev;
    char *value;
};

struct simple_cmd
{
    char *command;

    struct cmd_arg *args;

    fd_t stdin;
    fd_t stdout;
    fd_t stderr;

    int bg;
};

struct cmd
{
    struct simple_cmd *primary;
    struct cmd *secondary;

    enum
    {
        CMD_SIMPLE,
        CMD_SECONDARY_INPUT,
        CMD_SECONDARY_OR,
        CMD_SECONDARY_AND,
    } type;
};

struct simple_cmd *
parse_simple_cmd(const char *raw);

int
destroy_simple_cmd(struct simple_cmd *cmd);

// Consumes cmd even on failure
int
exec_cmd(struct cmd *cmd);

// Consumes cmd even on failure
int
fork_cmd(struct cmd *cmd, pid_t *pid);

// Consumes simple
struct cmd *
parse_cmd(struct simple_cmd *simple);

int
destroy_cmd(struct cmd *cmd);

void
dump_cmd(struct cmd *cmd);

#endif
