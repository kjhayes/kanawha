
#include <kanawha/file.h>
#include <kanawha/string.h>
#include <kanawha/kmalloc.h>
#include <kanawha/page_alloc.h>
#include <kanawha/stddef.h>
#include <kanawha/vmem.h>
#include <kanawha/assert.h>
#include <kanawha/kmalloc.h>
#include <kanawha/fs/path.h>
#include <kanawha/fs/node.h>

int
file_table_create(
        struct process *process)
{
    int res;

    struct file_table *table = kmalloc(sizeof(struct file_table));
    if(table == NULL) {
        return -ENOMEM;
    }
    memset(table, 0, sizeof(struct file_table));

    table->num_open_files = 0;
    spinlock_init(&table->lock);
    ptree_init(&table->descriptor_tree);
    ilist_init(&table->process_list);

    // Insert a dummy descriptor to make sure
    // that we don't assign NULL_FD to an actual
    // descriptor entry
    memset(&table->null_descriptor, 0, sizeof(table->null_descriptor));
    ptree_insert(&table->descriptor_tree, &table->null_descriptor.table_node, NULL_FD);

    res = file_table_attach(table, process);
    if(res) {
        kfree(table);
        return res;
    }

    return 0;
}

int
file_table_clone(
        struct file_table *parent,
        struct process *process)
{
    int res;
    printk("file_table_clone\n");

    struct file_table *child = kmalloc(sizeof(struct file_table));
    if(child == NULL) {
        return -ENOMEM;
    }
    memset(child, 0, sizeof(struct file_table));

    spin_lock(&parent->lock);

    child->num_open_files = parent->num_open_files;
    spinlock_init(&child->lock);
    ptree_init(&child->descriptor_tree);
    ilist_init(&child->process_list);

    memset(&child->null_descriptor, 0, sizeof(child->null_descriptor));
    ptree_insert(&child->descriptor_tree, &child->null_descriptor.table_node, NULL_FD);

    struct ptree_node *node = ptree_get_first(&parent->descriptor_tree);
    while(node != NULL)
    {
        DEBUG_ASSERT(KERNEL_ADDR(node));
        if(node->key == NULL_FD) {
            node = ptree_get_next(node);
            continue;
        }

        struct file *parent_file = container_of(node, struct file, table_node);
        struct file *child_file =
            kmalloc(sizeof(struct file));
        if(child_file == NULL) {
            return -ENOMEM;
        }
        memset(child_file, 0, sizeof(struct file));

        child_file->seek_offset = parent_file->seek_offset;
        child_file->dir_offset = parent_file->dir_offset;
        child_file->mode_flags = parent_file->mode_flags;
        child_file->access_flags = parent_file->access_flags;
        child_file->status_flags = parent_file->status_flags;

        res = fs_path_get(parent_file->path);
        if(res) {
            panic("Could not clone reference to fs path in file_table_clone! (err=%s)\n",
                    errnostr(res));
        }
        child_file->path = parent_file->path;
        child_file->refs = 1;

        ptree_insert(&child->descriptor_tree, &child_file->table_node, parent_file->table_node.key);

        node = ptree_get_next(node);
    }

    spin_unlock(&parent->lock);

    res = file_table_attach(child, process);
    if(res) {
        ptree_remove(&child->descriptor_tree, NULL_FD);
        struct ptree_node *node = ptree_get_first(&child->descriptor_tree);
        while(node != NULL) {
            file_table_close(child, process, node->key);
        }
        kfree(child);
        return res;
    }

    return 0;
}

int
file_table_attach(
        struct file_table *table,
        struct process *process)
{
    spin_lock(&table->lock);
    ilist_push_tail(&table->process_list, &process->file_table_node);
    process->file_table = table;
    spin_unlock(&table->lock);
    return 0;
}

// Called when refs == 0, or the table is being destroyed,
// must be called with table->lock held
static int
__file_table_free_descriptor(
        struct file_table *table,
        struct file *desc)
{
    int res;

    struct ptree_node *removed
        = ptree_remove(
                &table->descriptor_tree,
                desc->table_node.key);

    DEBUG_ASSERT(removed == &desc->table_node);

    if(removed->key == NULL_FD) {
        // This was the null descriptor of the table
        return 0;
    }

    DEBUG_ASSERT(KERNEL_ADDR(desc));
    DEBUG_ASSERT(KERNEL_ADDR(desc->path));

    res = fs_path_put(desc->path);

    if(res) {
        eprintk("Failed to put fs_path when closing file descriptor!\n");
        return res;
    }

    kfree(desc);
    table->num_open_files--;

    return 0;
}

int
file_table_deattach(
        struct file_table *table,
        struct process *process)
{
    spin_lock(&table->lock);

    ilist_remove(&table->process_list, &process->file_table_node);
    process->file_table = NULL;

    if(ilist_empty(&table->process_list)) {
        // We need to destroy this file table

        do {
            struct ptree_node *node =
                ptree_get_first(&table->descriptor_tree);
            if(node == NULL) {
                break;
            }
            struct file *desc =
                container_of(node, struct file, table_node);

            DEBUG_ASSERT(KERNEL_ADDR(table));
            DEBUG_ASSERT(KERNEL_ADDR(desc));
            __file_table_free_descriptor(table, desc);

        } while(1);

        DEBUG_ASSERT(table->num_open_files == 0);

        kfree(table);

    } else {
        // Some other process is still using the table
        spin_unlock(&table->lock);    
    }

    return 0;
}

int
file_table_open(
        struct file_table *table,
        struct process *process,
        const char *path_str,
        unsigned long access_flags,
        unsigned long mode_flags,
        fd_t *fd)
{
    int res;

    struct file *desc =
        kmalloc(sizeof(struct file));
    if(desc == NULL) {
        return -ENOMEM;
    }
    memset(desc, 0, sizeof(struct file));

    res = fs_path_lookup_for_process(
            process,
            path_str,
            access_flags,
            mode_flags,
            &desc->path);
    if(res) {
        kfree(desc);
        return res;
    }

    desc->refs = 1;
    // Done by memset above
    //desc->seek_offset = 0;
    //desc->dir_offset = 0;
    //desc->status_flags = 0;
    desc->mode_flags = mode_flags;
    desc->access_flags = access_flags;

    spin_lock(&table->lock);

    res = ptree_insert_any(
            &table->descriptor_tree,
            &desc->table_node);
    if(res) {
        spin_unlock(&table->lock);
        fs_path_put(desc->path);
        kfree(desc);
        return res;
    }

    table->num_open_files++;

    spin_unlock(&table->lock);

    *fd = desc->table_node.key;

    return 0;
}

int
file_table_close(
        struct file_table *table,
        struct process *process,
        fd_t fd)
{
    int res;

    if(fd == NULL_FD) {
        return -EINVAL;
    }

    spin_lock(&table->lock);

    struct ptree_node *table_node =
        ptree_get(&table->descriptor_tree, (uintptr_t)fd);

    if(table_node == NULL) {
        spin_unlock(&table->lock);
        return -ENXIO;
    }

    struct file *desc =
        container_of(table_node, struct file, table_node);

    DEBUG_ASSERT(desc->refs > 0);
    desc->refs--;
    desc->status_flags |= FILE_STATUS_CLOSED;

    if(desc->refs == 0) {
        res = __file_table_free_descriptor(table, desc);
        if(res) {
            eprintk("file_table_close_file: Failed to free descriptor with refs==0! (err=%s)\n",
                    errnostr(res));
            spin_unlock(&table->lock);
            return res;
        }
    }

    spin_unlock(&table->lock);
    return 0;
}

struct file *
file_table_get_file(
        struct file_table *table,
        struct process *process,
        fd_t fd)
{
    struct file *desc;
    spin_lock(&table->lock);

    struct ptree_node *node =
        ptree_get(&table->descriptor_tree, (uintptr_t)fd);

    if(node == NULL) {
        eprintk("PID(%ld) Tried to get non-existant file %ld\n",
            process->id, fd);
        desc = NULL;
    } else {
        desc = container_of(node, struct file, table_node);
        if(desc->status_flags & FILE_STATUS_CLOSED) {
            eprintk("PID(%ld) Tried to get closed file %ld\n",
                    process->id, fd);
            desc = NULL;
        } else {
            desc->refs++;
        }
    }

    spin_unlock(&table->lock);
    return desc;
}

int
file_table_put_file(
        struct file_table *table,
        struct process *process,
        struct file *desc)
{
    int res;
    spin_lock(&table->lock);

    DEBUG_ASSERT(desc->refs > 0);
    desc->refs--;
    if(desc->refs == 0) {
        res = __file_table_free_descriptor(table, desc);
    } else {
        res = 0;
    }

    spin_unlock(&table->lock);

    return res;
}

int
file_table_swap(
        struct file_table *table,
        fd_t fd0,
        fd_t fd1)
{
    int res;

    if(fd0 == fd1) {
        return 0;
    }

    spin_lock(&table->lock);

    struct ptree_node *rem;

    struct ptree_node *p0 =
        ptree_get(&table->descriptor_tree, fd0);
    if(p0 != NULL) {
        rem = ptree_remove(&table->descriptor_tree, fd0);
        DEBUG_ASSERT(rem == p0);
    }

    struct ptree_node *p1 =
        ptree_get(&table->descriptor_tree, fd1);
    if(p1 != NULL) {
        rem = ptree_remove(&table->descriptor_tree, fd1);
        DEBUG_ASSERT(rem == p1);
    }

    if(p0 != NULL) {
        p0->key = fd1;
        res = ptree_insert(&table->descriptor_tree, p0, fd1);
        if(res) {
            goto exit;
        }
    }

    if(p1 != NULL) {
        p1->key = fd0;
        ptree_insert(&table->descriptor_tree, p1, fd0);
        if(res) {
            goto exit;
        }
    }

    res = 0;

exit:
    spin_unlock(&table->lock);
    return res;
}

