#ifndef __KANAWHA__FILE_H__
#define __KANAWHA__FILE_H__

#include <kanawha/fs.h>
#include <kanawha/uapi/file.h>

struct file_descriptor
{
    struct ptree_node tree_node;

    int refs;

    size_t seek_offset;
    unsigned long access_flags;
    unsigned long mode_flags;

    struct fs_node *node;
};

struct file_table
{
    struct process *process;

    spinlock_t tree_lock;
    struct ptree descriptor_tree;
    size_t num_open_files;
};

// Initialize "process"'s file table as empty
int
file_table_init(
        struct process *process,
        struct file_table *table);

// Closes all file descriptors and frees all memory
int
file_table_deinit(
        struct process *process,
        struct file_table *table);

int
file_table_open_path(
        struct file_table *table,
        const char *path,
        unsigned long access_flags,
        unsigned long mode_flags,
        fd_t *fd);

int
file_table_open_child(
        struct file_table *table,
        fd_t parent,
        const char *name,
        unsigned long access_flags,
        unsigned long mode_flags,
        fd_t *fd);

int
file_table_open_mount(
        struct file_table* table,
        const char *attach_name,
        unsigned long access_flags,
        unsigned long mode_flags,
        fd_t *fd);

int
file_table_close_file(
        struct file_table *table,
        fd_t fd);

// Get the descriptor struct associated with fd,
// and refuse to allow the closing the file until
// file_table_put_descriptor is called
struct file_descriptor *
file_table_get_descriptor(
        struct file_table *table,
        fd_t fd);

int
file_table_put_descriptor(
        struct file_table *table,
        struct file_descriptor *desc);

#endif
