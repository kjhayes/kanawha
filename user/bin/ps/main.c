
#include <errno.h>
#include <fcntl.h>
#include <kanawha/sys-wrappers.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct proc
{
    pid_t id;
    pid_t parent;

    int idle;

    const char *exec;

    struct proc *next;
};

static const char *
read_string_file(int dir, const char *file)
{
    int res;
    int strfile = openat(dir, file, O_RDONLY);
    if(strfile < 0)
    {
        fprintf(stderr, "failed to open \"%s\"\n", file);
        return "???";
    }

    char buf[128] = {0};
    res = read(strfile, buf, 127);
    if(res <= 0)
    {
        return "???";
    }

    close(strfile);

    return strdup(buf);
}

static int
read_int_file(int dir, const char *file)
{
    int res;
    int strfile = openat(dir, file, O_RDONLY);
    if(strfile < 0)
    {
        fprintf(stderr, "failed to open \"%s\"\n", file);
        return strfile;
    }

    char buf[128] = {0};
    res = read(strfile, buf, 127);
    if(res < 0)
    {
        return res;
    }
    close(strfile);

    return strtol(buf, NULL, 0);
}

static struct proc *proc_list = NULL;

static inline int
init_proc(char *fname, int procfile)
{

    int res;

    struct proc *p = malloc(sizeof(*p));
    if(p == NULL)
    {
        return -ENOMEM;
    }
    memset(p, 0, sizeof(*p));

    // parse the procid
    p->id = strtol(fname, NULL, 0);
    // Don't consider ourselves
    if(p->id == getpid())
    {
        free(p);
        return 0;
    }

    // insert into the proc_list
    p->next = proc_list;
    proc_list = p;

    p->exec = read_string_file(procfile, "exec");
    p->parent = read_int_file(procfile, "parent");
    p->idle = read_int_file(procfile, "idle");

    return 0;
}

static inline void
print_proc(struct proc *p, int depth)
{
    for(int i = 0; i < depth; i++)
    {
        printf("\t");
    }
    printf("%s(%d) %d%%", p->exec, (int)p->id, 100 - p->idle);
    printf("\n");
}

static inline void
dump_proc(struct proc *p, int depth)
{
    print_proc(p, depth);

    struct proc **prev_slot;
    struct proc *i;

retry:
    prev_slot = &proc_list;
    i = proc_list;

    while(i)
    {
        if(i->parent == p->id)
        {
            // Remove "i" from the list
            *prev_slot = i->next;
            dump_proc(i, depth + 1);
            goto retry;
        }

        prev_slot = &i->next;
        i = i->next;
    }
}

static inline struct proc *
remove_proc(int id)
{

    struct proc **prev_slot;
    struct proc *i;

    prev_slot = &proc_list;
    i = proc_list;

    while(i)
    {
        if(i->id == id)
        {
            // Remove and return
            *prev_slot = i->next;
            return i;
        }

        prev_slot = &i->next;
        i = i->next;
    }

    return NULL;
}

int
main(int argc, const char **argv)
{
    int res;

    const char *dirpath = "/sys/proc/";

    int dir;
    res = kanawha_sys_open(dirpath, FILE_PERM_READ, 0, &dir);
    if(res)
    {
        fprintf(stderr, "failed to open \"%s\"\n", dirpath);
        exit(EXIT_FAILURE);
    }

    res = kanawha_sys_dirbegin(dir);
    while(res == 0)
    {
        char namebuf[128];
        res = kanawha_sys_dirname(dir, namebuf, 128);
        if(res)
        {
            break;
        }

        int procfile = dir;
        res = kanawha_sys_open(namebuf,
                               FILE_PERM_READ,
                               FILE_MODE_OPEN_RELATIVE,
                               &procfile);

        init_proc(namebuf, procfile);

        close(procfile);

        res = kanawha_sys_dirnext(dir);
    }

    struct proc *init = remove_proc(0);
    if(init == NULL)
    {
        fprintf(stderr, "could not find process 0!\n");
        return -1;
    }
    dump_proc(init, 0);

    return 0;
}
