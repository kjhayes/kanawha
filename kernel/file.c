
#include <kanawha/file.h>
#include <kanawha/string.h>
#include <kanawha/kmalloc.h>
#include <kanawha/page_alloc.h>
#include <kanawha/page_cache.h>
#include <kanawha/stddef.h>
#include <kanawha/vmem.h>
#include <kanawha/assert.h>
#include <kanawha/kmalloc.h>

static struct file_descriptor
null_file_descriptor = { 0 };

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
    ptree_insert(&table->descriptor_tree, &null_file_descriptor.tree_node, NULL_FD);

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
        struct file_descriptor *desc)
{
    int res;
    struct ptree_node *removed
        = ptree_remove(
                &table->descriptor_tree,
                desc->tree_node.key);

    DEBUG_ASSERT(removed == &desc->tree_node);

    res = fs_mount_put_node(
            desc->node->mount,
            desc->node);

    if(res) {
        eprintk("Failed to put fs_node when closing file descriptor!\n");
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
            struct file_descriptor *desc =
                container_of(node, struct file_descriptor, tree_node);

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
file_table_open_path(
        struct file_table *table,
        struct process *process,
        const char *path,
        unsigned long access_flags,
        unsigned long mode_flags,
        fd_t *fd)
{
    int res;

    struct fs_node *node;
    struct fs_mount *mnt;

    res = fs_path_lookup(
            path,
            &mnt,
            &node);
    if(res) {
        return res;
    }

    struct file_descriptor *desc;
    desc = kmalloc(sizeof(struct file_descriptor));
    if(desc == NULL) {
        return -ENOMEM;
    }
    memset(desc, 0, sizeof(struct file_descriptor));

    desc->node = node;
    desc->refs = 1;

    desc->seek_offset = 0;

    // We should be checking these against some form
    // of user/process permissions
    desc->mode_flags = mode_flags;
    desc->access_flags = access_flags;

    // Actually insert the descriptor into the table
    spin_lock(&table->lock);

    res = ptree_insert_any(&table->descriptor_tree, &desc->tree_node);
    if(res) {
        fs_mount_put_node(mnt, node);
        kfree(desc);
        spin_unlock(&table->lock);
        return -ENOMEM;
    }

    if(fd != NULL) {
        *fd = (fd_t)desc->tree_node.key;
    }

    table->num_open_files++;

    spin_unlock(&table->lock);

    return 0;
}

int
file_table_open_mount(
        struct file_table *table,
        struct process *process,
        const char *attach_name,
        unsigned long access_flags,
        unsigned long mode_flags,
        fd_t *fd)
{
    int res;

    struct fs_node *node;
    struct fs_mount *mnt;

    mnt = fs_mount_lookup(
            attach_name);
    if(mnt == NULL) {
        return -ENXIO;
    }

    size_t root_index;
    res = fs_mount_root_index(
            mnt,
            &root_index);
    if(res) {
        return res;
    }

    node = fs_mount_get_node(mnt, root_index);
    if(node == NULL) {
        eprintk("file_table_open_mount: received root index 0x%llx, but fs_mount_get_node failed! (err=%s)\n",
                (ull_t)root_index, errnostr(res));
        return -ENXIO;
    }

    struct file_descriptor *desc;
    desc = kmalloc(sizeof(struct file_descriptor));
    if(desc == NULL) {
        return -ENOMEM;
    }
    memset(desc, 0, sizeof(struct file_descriptor));

    desc->node = node;
    desc->refs = 1;

    // We should be checking these against some form
    // of user/process permissions
    desc->mode_flags = mode_flags;
    desc->access_flags = access_flags;

    // Actually insert the descriptor into the table
    spin_lock(&table->lock);

    res = ptree_insert_any(&table->descriptor_tree, &desc->tree_node);
    if(res) {
        fs_mount_put_node(mnt, node);
        kfree(desc);
        spin_unlock(&table->lock);
        return -ENOMEM;
    }

    if(fd != NULL) {
        *fd = (fd_t)desc->tree_node.key;
    }

    table->num_open_files++;

    spin_unlock(&table->lock);

    return 0;
}

int
file_table_open_child(
        struct file_table *table,
        struct process *process,
        fd_t parent,
        const char *name,
        unsigned long access_flags,
        unsigned long mode_flags,
        fd_t *fd)
{
    int res;

    struct file_descriptor *parent_desc =
        file_table_get_descriptor(table, process, parent);

    if(parent_desc == NULL) {
        return -EINVAL;
    }

    size_t num_children;
    res = fs_node_attr(parent_desc->node, FS_NODE_ATTR_CHILD_COUNT, &num_children);
    if(res) {
        file_table_put_descriptor(table, process, parent_desc);
        return res;
    }
    if(num_children == 0) {
        file_table_put_descriptor(table, process, parent_desc);
        return -ENXIO;
    }

    int found = 0;
    size_t found_index;
    size_t name_len = strlen(name);
    char name_buf[name_len+1];

    for(size_t i = 0; i < num_children; i++) {
        res = fs_node_child_name(
                parent_desc->node,
                i,
                name_buf,
                name_len);
        if(res) {
            wprintk("Failed to get fs_node child name during file_table_open_child! (err=%s)\n",
                    errnostr(res));
            continue;
        }
        name_buf[name_len] = '\0';
        if(strcmp(name_buf, name) == 0) {
            found_index = i;
            found = 1;
            break;
        }
    }

    if(!found) {
        file_table_put_descriptor(table, process, parent_desc);
        return -ENXIO;
    }

   
    size_t node_index;
    res = fs_node_get_child(parent_desc->node, found_index, &node_index);
    if(res) {
        file_table_put_descriptor(table, process, parent_desc);
        return res;
    }

    struct fs_node *node;
    node = fs_mount_get_node(parent_desc->node->mount, node_index);
    if(node == NULL) {
        file_table_put_descriptor(table, process, parent_desc);
        return -ENXIO;
    }

    // We don't need to keep the parent around anymore
    file_table_put_descriptor(table, process, parent_desc);

    struct file_descriptor *desc;
    desc = kmalloc(sizeof(struct file_descriptor));
    if(desc == NULL) {
        return -ENOMEM;
    }
    memset(desc, 0, sizeof(struct file_descriptor));

    desc->node = node;
    desc->refs = 1;

    // We should be checking these against some form
    // of user/process permissions
    desc->mode_flags = mode_flags;
    desc->access_flags = access_flags;

    // Actually insert the descriptor into the table
    spin_lock(&table->lock);

    res = ptree_insert_any(&table->descriptor_tree, &desc->tree_node);
    if(res) {
        fs_mount_put_node(node->mount, node);
        kfree(desc);
        spin_unlock(&table->lock);
        return -ENOMEM;
    }

    if(fd != NULL) {
        *fd = (fd_t)desc->tree_node.key;
    }

    table->num_open_files++;

    spin_unlock(&table->lock);

    return 0;

}

int
file_table_close_file(
        struct file_table *table,
        struct process *process,
        fd_t fd)
{
    int res;

    if(fd == NULL_FD) {
        return -EINVAL;
    }

    spin_lock(&table->lock);

    struct ptree_node *tree_node =
        ptree_get(&table->descriptor_tree, (uintptr_t)fd);

    if(tree_node == NULL) {
        spin_unlock(&table->lock);
        return -ENXIO;
    }

    struct file_descriptor *desc =
        container_of(tree_node, struct file_descriptor, tree_node);

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

struct file_descriptor *
file_table_get_descriptor(
        struct file_table *table,
        struct process *process,
        fd_t fd)
{
    struct file_descriptor *desc;
    spin_lock(&table->lock);

    struct ptree_node *node =
        ptree_get(&table->descriptor_tree, (uintptr_t)fd);

    if(node == NULL) {
        desc = NULL;
    } else {
        desc = container_of(node, struct file_descriptor, tree_node);
        desc->refs++;
    }

    spin_unlock(&table->lock);
    return desc;
}

int
file_table_put_descriptor(
        struct file_table *table,
        struct process *process,
        struct file_descriptor *desc)
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

