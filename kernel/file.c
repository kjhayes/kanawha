
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
        desc = NULL;
    } else {
        desc = container_of(node, struct file, table_node);
        desc->refs++;
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

