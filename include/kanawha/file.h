#ifndef __KANAWHA__FILE_H__
#define __KANAWHA__FILE_H__

#include <kanawha/fs/path.h>
#include <kanawha/uapi/file.h>
#include <kanawha/list.h>
#include <kanawha/process.h>

struct file_descriptor
{
    struct ptree_node tree_node;

    int refs;

    size_t seek_offset;
    unsigned long access_flags;
    unsigned long mode_flags;

    struct fs_path *path;
};

struct file_table
{
    spinlock_t lock;

    struct ptree descriptor_tree;
    struct file_descriptor null_descriptor;

    size_t num_open_files;

    ilist_t process_list;
};

int
file_table_create(
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
struct file_descriptor *
file_table_get_descriptor(
        struct file_table *table,
        struct process *process,
        fd_t fd);

int
file_table_put_descriptor(
        struct file_table *table,
        struct process *process,
        struct file_descriptor *desc);

#endif
