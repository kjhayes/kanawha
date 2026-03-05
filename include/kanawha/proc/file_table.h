#ifndef __KANAWHA__FILE_TABLE_H__
#define __KANAWHA__FILE_TABLE_H__

#include <kanawha/fs/file.h>
#include <kanawha/fs/path.h>
#include <kanawha/list.h>
#include <kanawha/proc/process.h>
#include <kanawha/uapi/file.h>

#define FILE_STATUS_CLOSED (1ULL << 0)

struct file_table
{
    thread_lock_t lock;

    struct ptree descriptor_tree;

    size_t num_open_files;

    ilist_t process_list;
};

int
file_table_create(struct process *process);

int
file_table_clone(struct file_table *table, struct process *process);

int
file_table_attach(struct file_table *table, struct process *process);

int
file_table_deattach(struct file_table *table, struct process *process);

int
file_table_open_node(struct file_table *table,
                     struct process *process,
                     struct fs_node *node,
                     unsigned long access_flags,
                     unsigned long mode_flags,
                     fd_t *fd);

int
file_table_open_path(struct file_table *table,
                     struct process *process,
                     struct fs_path *path,
                     unsigned long access_flags,
                     unsigned long mode_flags,
                     fd_t *fd);

int
file_table_open(struct file_table *table,
                struct process *process,
                struct fs_path *dir,
                const char *path,
                unsigned long access_flags,
                unsigned long mode_flags,
                fd_t *fd);

int
file_table_close(struct file_table *table, struct process *process, fd_t fd);

// Get the descriptor struct associated with fd,
// and refuse to allow the closing the file until
// file_table_put_descriptor is called
struct file *
file_table_get_file(struct file_table *table, struct process *process, fd_t fd);

int
file_table_put_file(struct file_table *table,
                    struct process *process,
                    struct file *file);

int
file_table_swap(struct file_table *table, fd_t f0, fd_t f1);

int
file_table_dup_into(struct file_table *table,
                    fd_t lowest_dst,
                    fd_t src,
                    fd_t *out);

// Closes all CLOSE_ON_EXEC files
int
file_table_on_exec(struct file_table *table, struct process *process);

#endif
