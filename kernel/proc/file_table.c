
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

static int
__file_table_close_lockless(struct file_table *table,
                            struct process *process,
                            struct file *desc);

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

    thread_lock_init(&child->lock);
    ptree_init(&child->descriptor_tree);
    ilist_init(&child->process_list);
    child->num_open_files = 0;

    struct ptree_node *node = ptree_get_first(&parent->descriptor_tree);
    while(node != NULL)
    {
        DEBUG_ASSERT(KERNEL_ADDR(node));

        struct file *parent_file = _fs_file_from_raw_file_table_node(node);
        if(parent_file == NULL) {
            break;
        }

        struct file *child_file = fs_file_clone(parent_file);
        if(child_file == NULL) {
            break;
        }
        struct ptree_node *child_node;
        child_node = _fs_file_to_raw_file_table_node(child_file);

        ptree_insert(&child->descriptor_tree,
                     child_node,
                     node->key);
        _fs_file_set_raw_file_table(child_file, child);

        child->num_open_files++;

        res = direct_file_on_open(child_file);
        if(res)
        {
            eprintk("fs_file_on_open returned %s!\n", errnostr(res));
            ptree_remove(&child->descriptor_tree, child_node->key);
            _fs_file_set_raw_file_table(child_file, NULL);
            fs_file_put(child_file);
            return res;
        }

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
            struct file *desc = _fs_file_from_raw_file_table_node(node);

            DEBUG_ASSERT(KERNEL_ADDR(table));
            DEBUG_ASSERT(KERNEL_ADDR(desc));
            __file_table_close_lockless(table, process, desc);
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
                     unsigned long internal_flags,
                     fd_t *fd)
{
    int res;

    struct file *desc;
    desc = fs_file_create(
            path,
            access_flags,
            mode_flags,
            internal_flags);
    if(desc == NULL) {
        return -ENOMEM;
    }
    struct ptree_node *table_node;
    table_node = _fs_file_to_raw_file_table_node(desc);

    thread_lock_acquire(&table->lock);

    res = ptree_insert_any(&table->descriptor_tree, table_node);
    if(res)
    {
        thread_lock_release(&table->lock);
        fs_file_put(desc);
        return res;
    }
    _fs_file_set_raw_file_table(desc, table);

    table->num_open_files++;

    res = direct_file_on_open(desc);
    if(res)
    {
        eprintk("fs_file_on_open returned %s!\n", errnostr(res));
        ptree_remove(&table->descriptor_tree, table_node->key);
        _fs_file_set_raw_file_table(desc, NULL);
        fs_file_put(desc);
        table->num_open_files--;
        thread_lock_release(&table->lock);
        return res;
    }

    thread_lock_release(&table->lock);

    if(fd) {
        *fd = fs_file_get_fd(desc);
    }

    return 0;
}

int
file_table_open(struct file_table *table,
                struct process *process,
                struct fs_path *dir,
                const char *path_str,
                unsigned long access_flags,
                unsigned long mode_flags,
                unsigned long internal_flags,
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
                               internal_flags,
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
                     unsigned long internal_flags,
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
                               internal_flags,
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

    DEBUG_ASSERT(KERNEL_ADDR(desc));
    DEBUG_ASSERT(table == fs_file_get_file_table(desc));

    res = direct_file_on_close(desc);
    if(res)
    {
        eprintk("fs_file_on_close returned %s!\n", errnostr(res));
        return res;
    }

    struct ptree_node *node = _fs_file_to_raw_file_table_node(desc);
    struct ptree_node *removed = ptree_remove(&table->descriptor_tree, node->key);
    DEBUG_ASSERT(removed == node);
    _fs_file_set_raw_file_table(desc, NULL);

    fs_file_put(desc);

    table->num_open_files--;
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

    struct file *desc = _fs_file_from_raw_file_table_node(table_node);
    if(desc == NULL) {
        thread_lock_release(&table->lock);
        return -EINVAL;
    }

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
        desc = _fs_file_from_raw_file_table_node(node);
        if(desc != NULL) {
            fs_file_get(desc);
        }
    }

    thread_lock_release(&table->lock);
    return desc;
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
    struct file *src_file = _fs_file_from_raw_file_table_node(open_node);

    while(ptree_get(&table->descriptor_tree, dst) != NULL)
    {
        dst++;
    }

    struct file *dst_file = fs_file_clone(src_file);
    if(dst_file == NULL)
    {
        res = -ENOMEM;
        goto exit;
    }
    struct ptree_node *dst_node = _fs_file_to_raw_file_table_node(dst_file);

    res = ptree_insert(&table->descriptor_tree, dst_node, dst);
    if(res)
    {
        fs_file_put(dst_file);
        goto exit;
    }
    _fs_file_set_raw_file_table(dst_file, table);

    table->num_open_files++;

    res = direct_file_on_open(dst_file);
    if(res)
    {
        eprintk("fs_file_on_open returned %s!\n", errnostr(res));
        ptree_remove(&table->descriptor_tree, dst);
        _fs_file_set_raw_file_table(dst_file, NULL);
        fs_file_put(dst_file);
        table->num_open_files--;
        thread_lock_release(&table->lock);
        return res;
    }

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

        struct file *desc = _fs_file_from_raw_file_table_node(pnode);
        if(desc == NULL) {
            break;
        }

        // Get the next node preemptively, in case we end up
        // deleting the current node.
        struct ptree_node *next = ptree_get_next(pnode);

        unsigned long mflags = fs_file_get_mode_flags(desc);
        if(mflags & FILE_MODE_CLOSE_ON_EXEC)
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
