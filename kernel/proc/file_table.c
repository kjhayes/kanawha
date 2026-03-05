
#include <kanawha/assert.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/path.h>
#include <kanawha/kmalloc.h>
#include <kanawha/page_alloc.h>
#include <kanawha/proc/file_table.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/vmem.h>

#ifdef CONFIG_DEBUG
/*
 * Handy to keep this function compiled in if we are debugging with GDB
 */

__maybe_unused static void
file_table_dump_lockless(struct file_table *table)
{
    printk("File Table: %p, attachments=%ld\n",
           table,
           (sl_t)ilist_count(&table->process_list));

    struct ptree_node *node = ptree_get_first(&table->descriptor_tree);
    while(node != NULL)
    {
        struct file *file = container_of(node, struct file, table_node);
        const char *name = fs_path_get_name(file->path);
        printk("\tDescriptor(%ld) refs=%ld, path=%p, %s\n",
               file->table_node.key,
               (sl_t)file->refs,
               file->path,
               name != NULL ? name : "(NULL)");
        node = ptree_get_next(node);
    }
}
#endif

int
file_table_create(struct process *process)
{
    int res;

    struct file_table *table = kzmalloc(sizeof(struct file_table), KM_KERNEL);
    if(table == NULL)
    {
        return -ENOMEM;
    }

    table->num_open_files = 0;
    thread_lock_init(&table->lock);
    ptree_init(&table->descriptor_tree);
    ilist_init(&table->process_list);

    res = file_table_attach(table, process);
    if(res)
    {
        kfree(table);
        return res;
    }

    return 0;
}

int
file_table_clone(struct file_table *parent, struct process *process)
{
    int res;
    dprintk("file_table_clone\n");

    struct file_table *child = kzmalloc(sizeof(struct file_table), KM_KERNEL);
    if(child == NULL)
    {
        return -ENOMEM;
    }

    thread_lock_acquire(&parent->lock);

    child->num_open_files = parent->num_open_files;
    thread_lock_init(&child->lock);
    ptree_init(&child->descriptor_tree);
    ilist_init(&child->process_list);

    struct ptree_node *node = ptree_get_first(&parent->descriptor_tree);
    while(node != NULL)
    {
        DEBUG_ASSERT(KERNEL_ADDR(node));

        struct file *parent_file = container_of(node, struct file, table_node);
        struct file *child_file = kzmalloc(sizeof(struct file), KM_KERNEL);
        if(child_file == NULL)
        {
            return -ENOMEM;
        }

        child_file->seek_offset = parent_file->seek_offset;
        child_file->dir_offset = parent_file->dir_offset;
        child_file->mode_flags = parent_file->mode_flags;
        child_file->access_flags = parent_file->access_flags;
        child_file->status_flags = parent_file->status_flags;

        res = fs_path_get(parent_file->path);
        if(res)
        {
            panic("Could not clone reference to fs path in "
                  "file_table_clone! "
                  "(err=%s)\n",
                  errnostr(res));
        }
        child_file->path = parent_file->path;
        child_file->refs = 1;

        ptree_insert(&child->descriptor_tree,
                     &child_file->table_node,
                     parent_file->table_node.key);

        node = ptree_get_next(node);
    }

    thread_lock_release(&parent->lock);

    res = file_table_attach(child, process);
    if(res)
    {
        struct ptree_node *node = ptree_get_first(&child->descriptor_tree);
        while(node != NULL)
        {
            file_table_close(child, process, node->key);
        }
        kfree(child);
        return res;
    }

    return 0;
}

int
file_table_attach(struct file_table *table, struct process *process)
{
    thread_lock_acquire(&table->lock);
    ilist_push_tail(&table->process_list, &process->file_table_node);
    process->file_table = table;
    thread_lock_release(&table->lock);
    return 0;
}

// Called when refs == 0, or the table is being destroyed,
// must be called with table->lock held
static int
__file_table_free_descriptor(struct file_table *table, struct file *desc)
{
    int res;

    struct ptree_node *removed =
        ptree_remove(&table->descriptor_tree, desc->table_node.key);

    DEBUG_ASSERT(removed == &desc->table_node);
    DEBUG_ASSERT(KERNEL_ADDR(desc));
    DEBUG_ASSERT(KERNEL_ADDR(desc->path));

    res = fs_path_put(desc->path);

    if(res)
    {
        eprintk("Failed to put fs_path when closing file descriptor!\n");
        return res;
    }

    kfree(desc);
    table->num_open_files--;

    return 0;
}

int
file_table_deattach(struct file_table *table, struct process *process)
{
    thread_lock_acquire(&table->lock);

    ilist_remove(&table->process_list, &process->file_table_node);
    process->file_table = NULL;

    if(ilist_empty(&table->process_list))
    {
        // We need to destroy this file table

        do
        {
            struct ptree_node *node = ptree_get_first(&table->descriptor_tree);
            if(node == NULL)
            {
                break;
            }
            struct file *desc = container_of(node, struct file, table_node);

            DEBUG_ASSERT(KERNEL_ADDR(table));
            DEBUG_ASSERT(KERNEL_ADDR(desc));
            __file_table_free_descriptor(table, desc);
        } while(1);

        DEBUG_ASSERT(table->num_open_files == 0);

        kfree(table);
    }
    else
    {
        // Some other process is still using the table
        thread_lock_release(&table->lock);
    }

    return 0;
}

int
file_table_open_path(struct file_table *table,
                     struct process *process,
                     struct fs_path *path,
                     unsigned long access_flags,
                     unsigned long mode_flags,
                     fd_t *fd)
{
    int res;

    struct file *desc = kzmalloc(sizeof(struct file), KM_KERNEL);
    if(desc == NULL)
    {
        return -ENOMEM;
    }

    fs_path_get(path);
    desc->path = path;

    desc->refs = 1;

    // Done by memset above
    // desc->seek_offset = 0;
    // desc->dir_offset = 0;
    // desc->status_flags = 0;
    desc->mode_flags = mode_flags;
    desc->access_flags = access_flags;

    thread_lock_acquire(&table->lock);

    res = ptree_insert_any(&table->descriptor_tree, &desc->table_node);
    if(res)
    {
        thread_lock_release(&table->lock);
        fs_path_put(desc->path);
        kfree(desc);
        return res;
    }

    table->num_open_files++;

    thread_lock_release(&table->lock);

    *fd = desc->table_node.key;

    return 0;
}

int
file_table_open(struct file_table *table,
                struct process *process,
                struct fs_path *dir,
                const char *path_str,
                unsigned long access_flags,
                unsigned long mode_flags,
                fd_t *fd)
{
    int res;

    struct fs_path *path;

    res = fs_path_lookup_for_process(process,
                                     dir,
                                     path_str,
                                     access_flags,
                                     mode_flags,
                                     &path);
    if(res)
    {
        dprintk("file_table_open: fs_path_lookup_for_process returned: %s\n",
                errnostr(res));
        return res;
    }

    res = file_table_open_path(table,
                               process,
                               path,
                               access_flags,
                               mode_flags,
                               fd);

    fs_path_put(path);
    return res;
}

int
file_table_open_node(struct file_table *table,
                     struct process *process,
                     struct fs_node *node,
                     unsigned long access_flags,
                     unsigned long mode_flags,
                     fd_t *fd)
{
    int res;
    struct fs_path *path;
    res = fs_path_create_anonymous(node, &path);
    if(res)
    {
        return res;
    }
    res = file_table_open_path(table,
                               process,
                               path,
                               access_flags,
                               mode_flags,
                               fd);
    fs_path_put(path);
    return res;
}

static int
__file_table_close_lockless(struct file_table *table,
                            struct process *process,
                            struct file *desc)
{
    int res;

    DEBUG_ASSERT(desc->refs > 0);
    desc->refs--;
    desc->status_flags |= FILE_STATUS_CLOSED;

    if(desc->refs == 0)
    {
        res = __file_table_free_descriptor(table, desc);
        if(res)
        {
            eprintk("file_table_close_file: Failed to free "
                    "descriptor with "
                    "refs==0! (err=%s)\n",
                    errnostr(res));
            return res;
        }
    }

    return 0;
}

int
file_table_close(struct file_table *table, struct process *process, fd_t fd)
{
    int res;

    thread_lock_acquire(&table->lock);

    struct ptree_node *table_node =
        ptree_get(&table->descriptor_tree, (uintptr_t)fd);

    if(table_node == NULL)
    {
        thread_lock_release(&table->lock);
        return -ENXIO;
    }

    struct file *desc = container_of(table_node, struct file, table_node);

    res = __file_table_close_lockless(table, process, desc);
    if(res)
    {
        thread_lock_release(&table->lock);
        return res;
    }

    thread_lock_release(&table->lock);
    return 0;
}

struct file *
file_table_get_file(struct file_table *table, struct process *process, fd_t fd)
{
    struct file *desc;
    thread_lock_acquire(&table->lock);

    struct ptree_node *node = ptree_get(&table->descriptor_tree, (uintptr_t)fd);

    if(node == NULL)
    {
        dprintk("PID(%ld) Tried to get non-existant file %ld\n",
                process->id,
                fd);
        desc = NULL;
    }
    else
    {
        desc = container_of(node, struct file, table_node);
        if(desc->status_flags & FILE_STATUS_CLOSED)
        {
            dprintk("PID(%ld) Tried to get closed file %ld\n", process->id, fd);
            desc = NULL;
        }
        else
        {
            desc->refs++;
        }
    }

    thread_lock_release(&table->lock);
    return desc;
}

int
file_table_put_file(struct file_table *table,
                    struct process *process,
                    struct file *desc)
{
    int res;
    thread_lock_acquire(&table->lock);

    DEBUG_ASSERT(desc->refs > 0);
    desc->refs--;
    if(desc->refs == 0)
    {
        res = __file_table_free_descriptor(table, desc);
    }
    else
    {
        res = 0;
    }

    thread_lock_release(&table->lock);

    return res;
}

int
file_table_swap(struct file_table *table, fd_t fd0, fd_t fd1)
{
    int res;

    if(fd0 == fd1)
    {
        return 0;
    }

    thread_lock_acquire(&table->lock);

    struct ptree_node *rem;

    struct ptree_node *p0 = ptree_get(&table->descriptor_tree, fd0);
    if(p0 != NULL)
    {
        rem = ptree_remove(&table->descriptor_tree, fd0);
        DEBUG_ASSERT(rem == p0);
    }

    struct ptree_node *p1 = ptree_get(&table->descriptor_tree, fd1);
    if(p1 != NULL)
    {
        rem = ptree_remove(&table->descriptor_tree, fd1);
        DEBUG_ASSERT(rem == p1);
    }

    if(p0 != NULL)
    {
        p0->key = fd1;
        res = ptree_insert(&table->descriptor_tree, p0, fd1);
        if(res)
        {
            goto exit;
        }
    }

    if(p1 != NULL)
    {
        p1->key = fd0;
        ptree_insert(&table->descriptor_tree, p1, fd0);
        if(res)
        {
            goto exit;
        }
    }

    res = 0;
exit:
    thread_lock_release(&table->lock);
    return res;
}

int
file_table_dup_into(struct file_table *table,
                    fd_t dst,
                    fd_t open_src,
                    fd_t *out)
{
    int res;

    thread_lock_acquire(&table->lock);

    struct ptree_node *open_node = ptree_get(&table->descriptor_tree, open_src);
    if(open_node == NULL)
    {
        res = -ENXIO;
        goto exit;
    }
    struct file *src_file = container_of(open_node, struct file, table_node);

    while(ptree_get(&table->descriptor_tree, dst) != NULL)
    {
        dst++;
    }

    struct file *dst_file = kzmalloc(sizeof(struct file), KM_KERNEL);
    if(dst_file == NULL)
    {
        res = -ENOMEM;
        goto exit;
    }

    dst_file->seek_offset = src_file->seek_offset;
    dst_file->dir_offset = src_file->dir_offset;
    dst_file->mode_flags = src_file->mode_flags;
    dst_file->access_flags = src_file->access_flags;
    dst_file->status_flags = src_file->status_flags;

    res = fs_path_get(src_file->path);
    if(res)
    {
        kfree(dst_file);
        goto exit;
    }
    dst_file->path = src_file->path;
    dst_file->refs = 1;

    res = ptree_insert(&table->descriptor_tree, &dst_file->table_node, dst);
    if(res)
    {
        fs_path_put(dst_file->path);
        kfree(dst_file);
        goto exit;
    }

    table->num_open_files++;

    res = 0;
    *out = dst;
exit:
    thread_lock_release(&table->lock);
    return res;
}

int
file_table_on_exec(struct file_table *table, struct process *process)
{
    int res;

    thread_lock_acquire(&table->lock);

    struct ptree_node *pnode = ptree_get_first(&table->descriptor_tree);
    while(pnode != NULL)
    {

        struct file *desc = container_of(pnode, struct file, table_node);

        // Get the next node preemptively, in case we end up
        // deleting the current node.
        struct ptree_node *next = ptree_get_next(pnode);

        if(desc->mode_flags & FILE_MODE_CLOSE_ON_EXEC)
        {
            res = __file_table_close_lockless(table, process, desc);
            if(res)
            {
                wprintk("Failed to close CLOSE_ON_EXEC file "
                        "during exec! (err=%s)\n",
                        errnostr(res));
            }
        }

        pnode = next;
    }

    thread_lock_release(&table->lock);

    return 0;
}
