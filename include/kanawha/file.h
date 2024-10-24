#ifndef __KANAWHA__FILE_H__
#define __KANAWHA__FILE_H__

#include <kanawha/fs/path.h>
#include <kanawha/uapi/file.h>
#include <kanawha/list.h>
#include <kanawha/process.h>

#define FILE_STATUS_CLOSED (1ULL<<0)

struct file
{
    struct ptree_node table_node;

    int refs;

    size_t seek_offset;
    size_t dir_offset;

    unsigned long status_flags;

    unsigned long access_flags;
    unsigned long mode_flags;

    struct fs_path *path;
};

struct file_table
{
    spinlock_t lock;

    struct ptree descriptor_tree;

    size_t num_open_files;

    ilist_t process_list;
};

int
file_table_create(
        struct process *process);

int
file_table_clone(
        struct file_table *table,
        struct process *process);

int
file_table_attach(
        struct file_table *table,
        struct process *process);

int
file_table_deattach(
        struct file_table *table,
        struct process *process);

int
file_table_open_path(
        struct file_table *table,
        struct process *process,
        struct fs_path *path,
        unsigned long access_flags,
        unsigned long mode_flags,
        fd_t *fd);

int
file_table_open(
        struct file_table *table,
        struct process *process,
        const char *path,
        unsigned long access_flags,
        unsigned long mode_flags,
        fd_t *fd);

int
file_table_close(
        struct file_table *table,
        struct process *process,
        fd_t fd);

// Get the descriptor struct associated with fd,
// and refuse to allow the closing the file until
// file_table_put_descriptor is called
struct file *
file_table_get_file(
        struct file_table *table,
        struct process *process,
        fd_t fd);

int
file_table_put_file(
        struct file_table *table,
        struct process *process,
        struct file *file);

int
file_table_swap(
        struct file_table *table,
        fd_t f0,
        fd_t f1);

#endif
