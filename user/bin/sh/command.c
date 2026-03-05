
#include "command.h"
#include <kanawha/environ.h>
#include <kanawha/process.h>
#include <kanawha/sys-wrappers.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
exec_simple_cmd(struct simple_cmd *cmd)
{
    int res;

    fd_t exec_file;

    // Determine the value of "argc" and how much data we will need to store
    // ARGV (Include the simple_cmd itself in ARGV)
    int argc = 1;

    for(struct cmd_arg *iter = cmd->args; iter != NULL; iter = iter->next)
    {
        if(iter->value == NULL)
        {
            // Need to evaluate the argument
            continue;
        }
        argc++;
    }

    const char *argv[argc + 1];
    memset(argv, 0, sizeof(argv));
    argv[0] = cmd->command;

    size_t argv_index = 1;
    for(struct cmd_arg *iter = cmd->args; iter != NULL; iter = iter->next)
    {
        if(iter->value == NULL)
        {
            // Need to evaluate the argument
            continue;
        }
        argv[argv_index] = iter->value;
        argv_index++;
    }

    argv[argc] = NULL;

    if(cmd->stdin != 0)
    {
        kanawha_sys_close(0);
        res = kanawha_sys_fmove(0, cmd->stdin, FMOVE_DUP, NULL);
        if(res)
        {
            goto err;
        }
    }
    if(cmd->stdout != 1)
    {
        kanawha_sys_close(1);
        res = kanawha_sys_fmove(1, cmd->stdout, FMOVE_DUP, NULL);
        if(res)
        {
            goto err;
        }
    }
    if(cmd->stderr != 2)
    {
        kanawha_sys_close(2);
        res = kanawha_sys_fmove(2, cmd->stderr, FMOVE_DUP, NULL);
        if(res)
        {
            goto err;
        }
    }

    // We leak argv here.

    res = execvp(cmd->command, (char *const *)argv);
    if(res)
    {
        goto err;
    }

    // We should never reach here
    return -EINVAL;

err:
    fprintf(stderr, "Failed to find command: \"%s\"\n", cmd->command);
    if(cmd)
    {
        destroy_simple_cmd(cmd);
    }

    return res;
}

// Consumes cmd even on failure
int
fork_simple_cmd(struct simple_cmd *cmd, pid_t *pid)
{
    int res;
    int child_pid = fork();

    if(child_pid == 0)
    {
        // We are the child
        res = exec_simple_cmd(cmd);
        // Should never reach here
        exit(res);
    }
    else
    {
        // We are the parent
        destroy_simple_cmd(cmd);
        *pid = child_pid;
        return 0;
    }
}

struct simple_cmd *
parse_simple_cmd(const char *raw)
{
    size_t line_len = strlen(raw);
    char line_copy[line_len + 1];
    memmove(line_copy, raw, line_len + 1);

    {
        char string_delimiter = '\0';
        char *iter = line_copy;
        while(*iter)
        {
            if(*iter == string_delimiter)
            {
                string_delimiter = '\0';
            }
            else if(*iter == '\'')
            {
                string_delimiter = '\'';
            }
            else if(*iter == '"')
            {
                string_delimiter = '"';
            }
            else if(string_delimiter == '\0' && isspace(*iter))
            {
                *iter = '\0';
            }
            iter++;
        }
    };

    struct simple_cmd *cmd = malloc(sizeof(struct simple_cmd));
    if(cmd == NULL)
    {
        goto err;
    }
    memset(cmd, 0, sizeof(struct simple_cmd));

    cmd->stdin = 0;
    cmd->stdout = 1;
    cmd->stderr = 2;
    cmd->bg = 0;

    {
        cmd->args = NULL;
        struct cmd_arg *cur_prev = NULL;
        struct cmd_arg **arg_slot = &cmd->args;
        size_t argc = 0;
        for(size_t i = 0; i < line_len; i++)
        {
            char *pot_arg = line_copy + i;
            size_t arglen = strlen(pot_arg);
            if(arglen > 0)
            {
                char *arg_copy = malloc(arglen + 1);
                if(arg_copy == NULL)
                {
                    goto err;
                }
                memcpy(arg_copy, pot_arg, arglen + 1);
                if(argc == 0)
                {
                    cmd->command = arg_copy;
                }
                else
                {
                    struct cmd_arg *arg = malloc(sizeof(struct cmd_arg));
                    if(arg == NULL)
                    {
                        goto err;
                    }
                    memset(arg, 0, sizeof(struct cmd_arg));
                    arg->value = arg_copy;
                    arg->next = NULL;
                    arg->prev = cur_prev;

                    *arg_slot = arg;
                    arg_slot = &arg->next;
                    cur_prev = arg;
                }
                argc++;
            }
            i += arglen;
        }
    }

    {
        struct cmd_arg *arg = cmd->args;
        while(arg->next)
        {
            arg = arg->next;
        }
        if(arg && (strcmp(arg->value, "&") == 0))
        {
            arg->prev->next = NULL;
            cmd->bg = 1;
            free(arg);
        }
    }

    return cmd;

err:
    if(cmd != NULL)
    {
        destroy_simple_cmd(cmd);
    }

    return NULL;
}

int
destroy_simple_cmd(struct simple_cmd *cmd)
{
    struct cmd_arg *prev_iter = NULL;
    for(struct cmd_arg *iter = cmd->args; iter != NULL; iter = iter->next)
    {
        if(prev_iter)
        {
            free(prev_iter);
        }

        if(iter->value)
        {
            free(iter->value);
        }

        prev_iter = iter;
    }
    if(prev_iter)
    {
        free(prev_iter);
    }

    if(cmd->command)
    {
        free(cmd->command);
    }

    free(cmd);

    return 0;
}

/*
 * Compound Commands
 */

void
dump_cmd(struct cmd *cmd)
{
    switch(cmd->type)
    {
    case CMD_SIMPLE:
        printf("SIMPLE(%s)(in=%p,out=%p,err=%p,bg=%d)",
               cmd->primary->command,
               (uintptr_t)cmd->primary->stdin,
               (uintptr_t)cmd->primary->stdout,
               (uintptr_t)cmd->primary->stderr,
               (int)cmd->primary->bg);
        break;
    case CMD_SECONDARY_INPUT:
        printf("(");
        dump_cmd(cmd->secondary);
        printf(" | SIMPLE(%s)(in=%p,out=%p,err=%p,bg=%d))",
               cmd->primary->command,
               (uintptr_t)cmd->primary->stdin,
               (uintptr_t)cmd->primary->stdout,
               (uintptr_t)cmd->primary->stderr,
               (int)cmd->primary->bg);
        break;
    case CMD_SECONDARY_AND:
        printf("(");
        dump_cmd(cmd->secondary);
        printf(" && SIMPLE(%s)(in=%p,out=%p,err=%p,bg=%d))",
               cmd->primary->command,
               (uintptr_t)cmd->primary->stdin,
               (uintptr_t)cmd->primary->stdout,
               (uintptr_t)cmd->primary->stderr,
               (int)cmd->primary->bg);
        break;
    case CMD_SECONDARY_OR:
        printf("(");
        dump_cmd(cmd->secondary);
        printf(" || SIMPLE(%s)(in=%p,out=%p,err=%p,bg=%d))",
               cmd->primary->command,
               (uintptr_t)cmd->primary->stdin,
               (uintptr_t)cmd->primary->stdout,
               (uintptr_t)cmd->primary->stderr,
               (int)cmd->primary->bg);
        break;
    default:
        printf("ERROR");
        break;
    }
}

int
exec_cmd(struct cmd *cmd)
{
    int res;
    struct simple_cmd *simple;
    pid_t primary, secondary;
    int primary_exit, secondary_exit;

    switch(cmd->type)
    {
    case CMD_SIMPLE:
        simple = cmd->primary;
        cmd->primary = NULL;
        destroy_cmd(cmd);
        return exec_simple_cmd(simple);
        break;
    case CMD_SECONDARY_INPUT:
        res = fork_cmd(cmd->secondary, &secondary);
        cmd->secondary = NULL;
        if(res)
        {
            destroy_cmd(cmd);
            return res;
        }
        res = fork_simple_cmd(cmd->primary, &primary);
        cmd->primary = NULL;
        if(res)
        {
            destroy_cmd(cmd);
            return res;
        }
        while(kanawha_sys_reap(0, &primary, &primary_exit))
        {
        }
        while(kanawha_sys_reap(0, &secondary, &secondary_exit))
        {
        }
        kanawha_sys_exit(primary_exit);
        break;
    default:
        destroy_cmd(cmd);
        return -EINVAL;
    }
}

// Consumes cmd even on failure
int
fork_cmd(struct cmd *cmd, pid_t *pid)
{
    int res;
    int child_pid = fork();
    if(child_pid == 0)
    {
        // We are the child
        res = exec_cmd(cmd);
        // Should never reach here
        exit(res);
    }
    else
    {
        // We are the parent
        destroy_cmd(cmd);
        *pid = child_pid;
        return 0;
    }
}

struct cmd *
parse_cmd(struct simple_cmd *simple)
{
    struct cmd *cmd = malloc(sizeof(struct cmd));
    if(cmd == NULL)
    {
        destroy_simple_cmd(simple);
        return NULL;
    }
    memset(cmd, 0, sizeof(struct cmd));

    // Get the last element of the argument list
    struct cmd_arg *last_arg = simple->args;
    while(last_arg && last_arg->next != NULL)
    {
        last_arg = last_arg->next;
    }

    struct cmd_arg *iter = last_arg;
    while(iter)
    {
        if(strcmp(iter->value, "|") == 0)
        {

            fd_t pipe_fd;
            int res = kanawha_sys_pipe(0, 0, &pipe_fd);
            if(res)
            {
                destroy_simple_cmd(simple);
                free(cmd);
                return NULL;
            }

            if(iter->prev)
            {
                iter->prev->next = NULL;
            }
            else
            {
                simple->args = NULL;
            }
            iter->prev = NULL;

            fd_t primary_stdout = simple->stdout;
            fd_t primary_stderr = simple->stderr;

            simple->stdout = pipe_fd;
            simple->stderr = pipe_fd;
            cmd->secondary = parse_cmd(simple);

            struct cmd_arg *primary_args = iter->next;
            free(iter->value);
            free(iter);

            if(primary_args == NULL)
            {
                fprintf(stderr, "Missing command after \"|\"!\n");
                destroy_cmd(cmd->secondary);
                free(cmd);
                return NULL;
            }

            struct simple_cmd *primary = malloc(sizeof(struct simple_cmd));
            if(primary == NULL)
            {
                destroy_cmd(cmd->secondary);
                free(cmd);
                return NULL;
            }
            memset(primary, 0, sizeof(struct simple_cmd));

            primary->stdin = pipe_fd;
            primary->stdout = primary_stdout;
            primary->stderr = primary_stderr;

            primary->command = primary_args->value;
            primary->args = primary_args->next;
            free(primary_args);

            cmd->type = CMD_SECONDARY_INPUT;
            cmd->primary = primary;
            return cmd;
        }
        iter = iter->prev;
    }

    cmd->type = CMD_SIMPLE;
    cmd->primary = simple;
    return cmd;
}

int
destroy_cmd(struct cmd *cmd)
{
    if(cmd->primary)
    {
        destroy_simple_cmd(cmd->primary);
    }
    if(cmd->secondary)
    {
        destroy_cmd(cmd->secondary);
    }

    free(cmd);

    return 0;
}
