

#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/ptree.h>
#include <kanawha/stddef.h>
#include <kanawha/list.h>
#include <kanawha/page_alloc.h>
#include <kanawha/lock.h>
#include <kanawha/string.h>
#include <kanawha/fs/type.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>

#define RAMFS_PAGE_ORDER 12

struct ramfs_node
{
    struct ptree_node inode_node;

    struct fs_node_ops *node_ops;
    struct fs_file_ops *file_ops;

    struct ptree page_tree;
    size_t size;

    atomic_t dirent_refs;
    ilist_t directory;
};

struct ramfs_dirent {
    ilist_node_t list_node;
    char *name;
    size_t inode;
};

struct ramfs_page
{
    struct ptree_node node;
    void __phys *page;
};

struct ramfs_mount
{
    struct fs_mount fs_mount;

    thread_lock_t inode_lock;
    struct ptree inode_tree;

    struct ramfs_node root_node;
};


#define ROOT_INODE_INDEX (0)

static struct fs_node_ops ramfs_file_node_ops;
static struct fs_file_ops ramfs_file_file_ops;
static struct fs_node_ops ramfs_dir_node_ops;
static struct fs_file_ops ramfs_dir_file_ops;

// Regular File fs_node

static int
ramfs_file_load_page(
	struct fs_node *fs_node,
	uintptr_t pfn,
	unsigned long flags,
	void __phys **addr_out)
{
    int res;

    struct ramfs_node *node = fs_node->backing.priv_state;

    struct ptree_node *pnode = ptree_get(&node->page_tree, pfn);

    if(pnode == NULL)
    {
	if(flags & FS_NODE_LOAD_PAGE_MAY_CREATE) {
	    struct ramfs_page *page = kmalloc(sizeof(*page));
	    if(page == NULL) {
		return -ENOMEM;
	    }
	    memset(page, 0, sizeof(*page));

	    res = page_alloc(RAMFS_PAGE_ORDER, &page->page, 0);
	    if(res) {
		kfree(page);
		return res;
	    }

	    memset_p(page->page, 0, 1ULL<<RAMFS_PAGE_ORDER);

	    ptree_insert(&node->page_tree, &page->node, pfn);

	    pnode = &page->node;

	} else {
	    return -ENXIO;
	}
    }

    struct ramfs_page *page = container_of(pnode, struct ramfs_page, node);

    *addr_out = page->page;

    return 0;
}

static int
ramfs_file_unload_page(
	struct fs_node *fs_node,
	uintptr_t pfn,
	unsigned long flags,
	void __phys *addr)
{
    // TODO
    return 0;
}

static int
ramfs_file_free_all_pages(
	struct ramfs_node *node)
{
    struct ptree_node *pnode;
    do {
	pnode = ptree_get_first(&node->page_tree);
	if(pnode == NULL) {
	    break;
	}
	ptree_remove(&node->page_tree, pnode->key);
	struct ramfs_page *page = container_of(pnode, struct ramfs_page, node);
	page_free(RAMFS_PAGE_ORDER, page->page);
    } while(1);

    return 0;
}

static int
ramfs_file_resize(
	struct ramfs_node *node,
	size_t new_size)
{
    if(new_size >= node->size) {
	node->size = new_size;
	return 0;
    }

    // We need to shrink

    if(new_size == 0) {
	return ramfs_file_free_all_pages(node);
    }

    // Will add an unnecessary page in some cases
    // (part of the reason we special case resizing to zero)
    uintptr_t new_num_pages = (new_size >> RAMFS_PAGE_ORDER) + 1;

    struct ptree_node *pnode;
    do {
	pnode = ptree_get_min_greater_or_eq(&node->page_tree, new_num_pages);
	if(pnode == NULL) {
	    break;
	}
	ptree_remove(&node->page_tree, pnode->key);
	struct ramfs_page *page = container_of(pnode, struct ramfs_page, node);
	page_free(RAMFS_PAGE_ORDER, page->page);
    } while(1);

    node->size = new_size;

    return 0;
}

static int
ramfs_file_getattr(
        struct fs_node *fs_node,
        int attr,
        size_t *value)
{
    struct ramfs_node *node = fs_node->backing.priv_state;

    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
            *value = node->size;
            break;
        case FS_NODE_ATTR_PAGE_ORDER:
            *value = RAMFS_PAGE_ORDER;
            break;
        case FS_NODE_ATTR_TYPES:
            *value = FS_NODE_TYPE_REGULAR;
            break;
        default:
            return -EINVAL;
    }

    return 0;
}

static int
ramfs_file_setattr(
        struct fs_node *fs_node,
        int attr,
        size_t value)
{
    struct ramfs_node *node = fs_node->backing.priv_state;

    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
	    return ramfs_file_resize(node, value);
    }

    return -EINVAL;
}

static int
ramfs_file_flush_page(
	struct fs_node *node,
	uintptr_t pfn,
	unsigned long flags)
{
    return 0;
}

static struct fs_node_ops
ramfs_file_node_ops =
{
    .load_page = ramfs_file_load_page,
    .unload_page = ramfs_file_unload_page,

    .getattr = ramfs_file_getattr,
    .setattr = ramfs_file_setattr,

    .flush = fs_node_flush_nop,
    .flush_page = fs_node_flush_page_nop,

    .read_page = fs_node_cannot_read_page,
    .write_page = fs_node_cannot_write_page,

    .link = fs_node_cannot_link,
    .unlink = fs_node_cannot_unlink,
    .symlink = fs_node_cannot_symlink,
    .lookup = fs_node_cannot_lookup,
    .mkdir = fs_node_cannot_mkdir,
    .mkfifo = fs_node_cannot_mkfifo,
    .mkfile = fs_node_cannot_mkfile,
};

static struct fs_file_ops
ramfs_file_file_ops =
{
    .read = fs_file_paged_read,
    .write = fs_file_paged_write,
    .seek = fs_file_paged_seek,
    .flush = fs_file_paged_flush,

    .poll = fs_file_cannot_poll,

    .dir_next = fs_file_cannot_dir_next,
    .dir_begin = fs_file_cannot_dir_begin,
    .dir_readattr = fs_file_cannot_dir_readattr,
    .dir_readname = fs_file_cannot_dir_readname,
};

static int
ramfs_dir_getattr(
        struct fs_node *fs_node,
        int attr,
        size_t *value)
{
    struct ramfs_node *node = fs_node->backing.priv_state;

    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
            *value = node->size;
            break;
        case FS_NODE_ATTR_PAGE_ORDER:
            *value = RAMFS_PAGE_ORDER;
            break;
        case FS_NODE_ATTR_TYPES:
            *value = FS_NODE_TYPE_DIRECTORY;
            break;
        default:
            return -EINVAL;
    }

    return 0;
}

static int
ramfs_dir_setattr(
        struct fs_node *fs_node,
        int attr,
        size_t value)
{
    struct ramfs_node *node = fs_node->backing.priv_state;

    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
	    if(value == 0) {
                return 0;
	    } else {
		return -EINVAL;
	    }
	    break;
    }

    return -EINVAL;
}

static int
ramfs_dir_lookup(
	struct fs_node *fs_node,
	const char *name,
	size_t *inode)
{
    struct ramfs_node *node = fs_node->backing.priv_state;

    ilist_node_t *iter;

    ilist_for_each(iter, &node->directory) {
	struct ramfs_dirent *dirent =
	    container_of(iter, struct ramfs_dirent, list_node);
	if(strcmp(dirent->name, name) == 0) {
	    *inode = dirent->inode;
	    return 0;
	}
    }

    return -ENXIO;
}

static int
ramfs_create_link(
	struct ramfs_node *dir,
	struct ramfs_node *child,
	const char *name)
{
    struct ramfs_dirent *dirent = kmalloc(sizeof(*dirent));
    if(dirent == NULL) {
	return -ENOMEM;
    }
    memset(dirent, 0, sizeof(*dirent));

    dirent->name = kstrdup(name);
    if(dirent->name == NULL) {
	kfree(dirent);
	return -ENOMEM;
    }
    dirent->inode = child->inode_node.key;

    atomic_fetch_inc(&child->dirent_refs);

    ilist_push_tail(&dir->directory, &dirent->list_node);

    return 0;
}

static int
ramfs_dir_mkfile(
	struct fs_node *fs_node,
	const char *filename,
	unsigned long flags)
{
    int res;

    struct ramfs_node *dir = fs_node->backing.priv_state;

    struct ramfs_node *child = kmalloc(sizeof(*child));
    if(child == NULL) {
	return -ENOMEM;
    }
    memset(child, 0, sizeof(*child));

    child->size = 0;
    child->node_ops = &ramfs_file_node_ops;
    child->file_ops = &ramfs_file_file_ops;
    ilist_init(&child->directory);
    atomic_set_relaxed(&child->dirent_refs, 0);
    ptree_init(&child->page_tree);

    struct ramfs_mount *mnt = container_of(fs_node->mount, struct ramfs_mount, fs_mount);

    thread_lock_acquire(&mnt->inode_lock);
    res = ptree_insert_any(&mnt->inode_tree, &child->inode_node);
    if(res) {
	kfree(child);
	return res;
    }
    thread_lock_release(&mnt->inode_lock);

    res = ramfs_create_link(dir, child, filename);
    if(res) {
	ptree_remove(&mnt->inode_tree, child->inode_node.key);
	kfree(child);
	return res;
    }

    return 0;
}

static int
ramfs_dir_mkdir(
	struct fs_node *fs_node,
	const char *filename,
	unsigned long flags)
{
    int res;

    struct ramfs_node *dir = fs_node->backing.priv_state;

    struct ramfs_node *child = kmalloc(sizeof(*child));
    if(child == NULL) {
	return -ENOMEM;
    }
    memset(child, 0, sizeof(*child));

    child->size = 0;
    child->node_ops = &ramfs_dir_node_ops;
    child->file_ops = &ramfs_dir_file_ops;
    ilist_init(&child->directory);
    atomic_set_relaxed(&child->dirent_refs, 0);
    ptree_init(&child->page_tree);

    struct ramfs_mount *mnt = container_of(fs_node->mount, struct ramfs_mount, fs_mount);

    thread_lock_acquire(&mnt->inode_lock);
    res = ptree_insert_any(&mnt->inode_tree, &child->inode_node);
    if(res) {
	kfree(child);
	return res;
    }
    thread_lock_release(&mnt->inode_lock);

    res = ramfs_create_link(dir, child, filename);
    if(res) {
	ptree_remove(&mnt->inode_tree, child->inode_node.key);
	kfree(child);
	return res;
    }

    return 0;
}

static struct ramfs_dirent *
ramfs_get_current_dirent(
	struct file *file)
{
    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    struct ramfs_node *node = fs_node->backing.priv_state;

    size_t offset = 0;

    if(ilist_empty(&node->directory)) {
	return NULL;
    }

    struct ramfs_dirent *cur;
    ilist_node_t *iter;
    ilist_for_each(iter, &node->directory) {
	if(offset == file->dir_offset) {
	    return container_of(iter, struct ramfs_dirent, list_node);
	}
	offset++;
    }

    return NULL;
}

int
ramfs_dir_dir_begin(
	struct file *file)
{
    file->dir_offset = 0;
    return 0;
}

int
ramfs_dir_dir_next(
	struct file *file)
{
    file->dir_offset++;
    struct ramfs_dirent *dirent = ramfs_get_current_dirent(file);
    if(dirent == NULL) {
	return -ENXIO;
    }
    return 0;
}

int
ramfs_dir_dir_readattr(
	struct file *file,
	int attr,
	size_t *value)
{
    return -EUNIMPL;
}

int
ramfs_dir_dir_readname(
	struct file *file,
	char *buffer,
	size_t buflen)
{
    struct ramfs_dirent *dirent = ramfs_get_current_dirent(file);
    if(dirent == NULL) {
	return -EINVAL;
    }

    DEBUG_ASSERT(KERNEL_ADDR(dirent));
    DEBUG_ASSERT(KERNEL_ADDR(dirent->name));

    strncpy(buffer, dirent->name, buflen);
    buffer[buflen-1] = '\0';

    return 0;
}

int
ramfs_dir_unlink(
	struct fs_node *fs_node,
	const char *name)
{
    dprintk("ramfs_dir_unlink\n");
    struct ramfs_node *node = fs_node->backing.priv_state;

    size_t inode;
  
    int found = 0;
    ilist_node_t *iter;
    ilist_for_each(iter, &node->directory) {
	struct ramfs_dirent *dirent = container_of(iter, struct ramfs_dirent, list_node);
	if(strcmp(dirent->name, name) == 0) {
	    inode = dirent->inode;
	    found = 1;
	    ilist_remove(&node->directory, iter);
	    kfree(dirent->name);
	    kfree(dirent);
	    break;
	}
    }

    if(!found) {
	dprintk("Failed to find \"%s\"\n", name);
	return -EINVAL;
    }

    // Decrement the references to the inode

    struct ramfs_mount *mnt = container_of(fs_node->mount, struct ramfs_mount, fs_mount);

    thread_lock_acquire(&mnt->inode_lock);
    struct ptree_node *pnode = ptree_get(&mnt->inode_tree, inode);
    if(pnode == NULL) {
	// Removed an invalid dirent?
	dprintk("Failed to find inode %d\n", (int)inode);
        thread_lock_release(&mnt->inode_lock);
	return 0;
    }
    struct ramfs_node *linked_to = container_of(pnode, struct ramfs_node, inode_node);

    if(!ilist_empty(&linked_to->directory)) {
	// Cannot remove non-empty directory
	dprintk("Cannot remove non-empty directory\n");
        thread_lock_release(&mnt->inode_lock);
	return -EINVAL;
    }

    atomic_val_t refs = atomic_fetch_dec(&linked_to->dirent_refs);
    if(refs == 1) {
	// We just closed the last reference to this node
	ptree_remove(&mnt->inode_tree, linked_to->inode_node.key);
	ramfs_file_free_all_pages(linked_to);
	kfree(linked_to);
    }
    thread_lock_release(&mnt->inode_lock);

    return 0;
}

static struct fs_node_ops
ramfs_dir_node_ops =
{
    .lookup = ramfs_dir_lookup,
    .mkdir = ramfs_dir_mkdir,
    .mkfile = ramfs_dir_mkfile,
    .getattr = ramfs_dir_getattr,
    .setattr = ramfs_dir_setattr,

    .flush = fs_node_flush_nop,
    .flush_page = fs_node_flush_page_nop,

    .unlink = ramfs_dir_unlink,

    .link = fs_node_cannot_link,
    .symlink = fs_node_cannot_symlink, 
    .mkfifo = fs_node_cannot_mkfifo,
    .load_page = fs_node_cannot_load_page,
    .unload_page = fs_node_cannot_unload_page,
    .read_page = fs_node_cannot_read_page,
    .write_page = fs_node_cannot_write_page,
};

static struct fs_file_ops
ramfs_dir_file_ops =
{
    .dir_begin = ramfs_dir_dir_begin,
    .dir_next = ramfs_dir_dir_next,
    .dir_readattr = ramfs_dir_dir_readattr,
    .dir_readname = ramfs_dir_dir_readname,

    .flush = fs_file_nop_flush,

    .read = fs_file_cannot_read,
    .write = fs_file_cannot_write,
    .poll = fs_file_cannot_poll,
    .seek = fs_file_cannot_seek,
};


// Mount

static int
ramfs_mount_root_index(
        struct fs_mount *mnt,
        size_t *root_index)
{
    *root_index = ROOT_INODE_INDEX;
    return 0;
}

static int
ramfs_mount_load_node(
        struct fs_mount *fs_mount,
        size_t node_index,
	struct fs_node *fs_node)
{
    struct ramfs_mount *mnt = container_of(fs_mount, struct ramfs_mount, fs_mount);

    thread_lock_acquire(&mnt->inode_lock);
    struct ptree_node *pnode = ptree_get(&mnt->inode_tree, node_index);
    if(pnode == NULL) {
	return -ENXIO;
    }
    thread_lock_release(&mnt->inode_lock);

    struct ramfs_node *node = container_of(pnode, struct ramfs_node, inode_node);

    fs_node->backing.file_ops = node->file_ops;
    fs_node->backing.node_ops = node->node_ops;
    fs_node->backing.priv_state = node;

    return 0;
}

static int
ramfs_mount_unload_node(
        struct fs_mount *fs_mount,
	size_t node_index,
        struct fs_node *fs_node)
{
    struct ramfs_mount *mnt = container_of(fs_mount, struct ramfs_mount, fs_mount);

    return 0;
}

static struct fs_mount_ops
ramfs_mount_ops = {
    .root_index = ramfs_mount_root_index,
    .load_node = ramfs_mount_load_node,
    .unload_node = ramfs_mount_unload_node,
    .sync = fs_mount_nop_sync,
};

// ramfs FS type

static int
ramfs_type_mount_special(
        struct fs_type *type,
        const char *id,
        struct fs_mount **out)
{
    if(strcmp(id, "ramfs") != 0) {
	return  -EINVAL;
    }

    struct ramfs_mount *mnt = kmalloc(sizeof(*mnt));
    if(mnt == NULL) {
	return -ENOMEM;
    }
    memset(mnt, 0, sizeof(*mnt));

    init_fs_mount_struct(&mnt->fs_mount, &ramfs_mount_ops);

    thread_lock_init(&mnt->inode_lock);
    ptree_init(&mnt->inode_tree);

    mnt->root_node.node_ops = &ramfs_dir_node_ops;
    mnt->root_node.file_ops = &ramfs_dir_file_ops;
    ptree_init(&mnt->root_node.page_tree);
    mnt->root_node.size = 0;
    ilist_init(&mnt->root_node.directory);
    mnt->root_node.dirent_refs = 1;

    ptree_insert(&mnt->inode_tree, &mnt->root_node.inode_node, ROOT_INODE_INDEX);

    *out = &mnt->fs_mount;

    return 0;
}

static int
ramfs_type_unmount(
        struct fs_type *type,
        struct fs_mount *mnt)
{
    return -EUNIMPL;
}

struct fs_type ramfs_fs_type = {
    .mount_file = fs_type_cannot_mount_file,
    .mount_special = ramfs_type_mount_special,
    .unmount = ramfs_type_unmount,
};

static int
ramfs_register_fs_type(void)
{
    int res;
    res = register_fs_type(
            &ramfs_fs_type,
            "ramfs");
    if(res) {
        return res;
    }
    return 0;
}
declare_init_desc(fs, ramfs_register_fs_type, "Registering RAMFS Filesystem");

