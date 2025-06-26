
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/spawn.h>
#include <kanawha/exec.h>
#include <kanawha/environ.h>
#include <elk-libc-internal/exec_path.h>
#include <elk-libc-internal/argv.h>

int
execve(
    const char *cmd,
    char *const __argv[],
    char *const __envp[])
{
    char **argv = (char **)__argv;

    int res;
    fd_t exec_file;
    res = __elk_libc__exec_path_lookup(cmd, &exec_file);
    if(res) {
        errno = res;
        return -1;
    }

    // Clear the environment
    res = kanawha_sys_environ(NULL,NULL,0, ENV_WIPE);
    if(res) {
        errno = res;
        return -1;
    }

    // Set up the new environment
    char **envp = (char**)__envp;
    while(*envp) {
        putenv(*envp);
        envp++;
    }

    int argc = 0;
    while(argv[argc] != NULL) {argc++;}

    res = __elk_libc__set_argv(argc, argv);
    if(res) {
        kanawha_sys_close(exec_file);
        return res;
    }

    return kanawha_sys_exec(exec_file, 0);
}

