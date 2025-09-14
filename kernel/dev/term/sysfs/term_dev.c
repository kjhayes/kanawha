
#include <kanawha/dev/term.h>
#include <kanawha/dev/term/sysfs.h>

#include <kanawha/types.h>
#include <kanawha/init.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/lock.h>
#include <kanawha/kmalloc.h>
#include <kanawha/fs/type.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>

struct vfs_mount *term_dev_fs_mount = NULL;

static int
term_dev_fs_node_init_all_nodes(
	struct term_dev_fs_node *node)
{
    int res;

    res = term_dev_fs_node_init_stream(node);
    if(res) {
	return res;
    }

    res = term_dev_fs_node_init_baudrate(node);
    if(res) {
	term_dev_fs_node_deinit_stream(node);
	return res;
    }

    res = term_dev_fs_node_init_raw(node);
    if(res) {
	term_dev_fs_node_deinit_stream(node);
	term_dev_fs_node_deinit_baudrate(node);
	return res;
    }


    return 0;
}

static int
term_dev_fs_node_deinit_all_nodes(
	struct term_dev_fs_node *node)
{
    int res;

    term_dev_fs_node_deinit_stream(node);
    term_dev_fs_node_deinit_baudrate(node);
    term_dev_fs_node_deinit_raw(node);

    return 0;
}

static int
term_dev_fs_node_link_nodes(
	struct term_dev_fs_node *node)
{
    int res;

    res = vfs_mount_link_root(
	    term_dev_fs_mount,
	    term_dev_get_name(node->dev),
	    node->stream_vfs_node.inode_node.key);
    if(res) {
	return res;
    }

    res = vfs_node_link(
	    &node->stream_vfs_node,
	    "baud",
	    node->baudrate_vfs_node.inode_node.key);
    if(res) {
        vfs_mount_unlink_root(
	    term_dev_fs_mount,
	    term_dev_get_name(node->dev));
	return res;
    }

    res = vfs_node_link(
	    &node->stream_vfs_node,
	    "raw",
	    node->raw_vfs_node.inode_node.key);
    if(res) {
        vfs_mount_unlink_root(
	    term_dev_fs_mount,
	    term_dev_get_name(node->dev));
	vfs_node_unlink(
		&node->stream_vfs_node,
		"baud");
	return res;
    }
    return 0;
}

//static int
//term_dev_fs_node_unlink_nodes(
//	struct term_dev_fs_node *node)
//{
//    vfs_mount_unlink_root(
//	    term_dev_fs_mount,
//	    term_dev_get_name(node->dev));
//    vfs_node_unlink(
//    	    &node->stream_vfs_node,
//    	    "baud");
//    vfs_node_unlink(
//    	    &node->stream_vfs_node,
//    	    "raw");
//    return 0;
//}

static void
term_dev_fs_on_register(
        struct term_dev *dev
        )
{
    int res;
    struct term_dev_fs_node *node = kmalloc(sizeof(*node), KM_KERNEL);
    if(node == NULL) {
        return;
    }
    node->dev = dev;

    res = term_dev_fs_node_init_all_nodes(node);
    if(res) {
	kfree(node);
	return;
    }

    res = term_dev_fs_node_link_nodes(node);
    if(res) {
	term_dev_fs_node_deinit_all_nodes(node);
	kfree(node);
	return;
    }
}

static struct term_dev_registry_hook *term_dev_fs_hook = NULL;

static void
term_dev_fs_on_unregister(
        struct term_dev *dev
        )
{
    panic("Tried to deregister term device! (UNIMPL)\n");
}

static int
term_dev_init_fs_mount(void)
{
    int res;

    struct vfs_mount *mnt;
    mnt = vfs_mount_create();
    if(mnt == NULL) {
        eprintk("Failed to create term_dev VFS mount!\n");
        return -ENOMEM;
    }

    term_dev_fs_mount = mnt;

    struct term_dev_registry_hook *hook;
    hook = hook_term_dev_registry(
            term_dev_fs_on_register,
            term_dev_fs_on_unregister
            );
    if(hook == NULL) {
        term_dev_fs_mount = NULL;
        vfs_mount_destroy(mnt);
        return -ENOMEM;
    }

    term_dev_fs_hook = hook;

    res = sysfs_register_mount(&term_dev_fs_mount->fs_mount, "termdev");
    if(res) {
        term_dev_fs_mount = NULL;
        vfs_mount_destroy(mnt);
        term_dev_fs_hook = NULL;
        unhook_term_dev_registry(hook);
        return res;
    }

    return 0;
}
declare_init_desc(fs, term_dev_init_fs_mount, "Registering termdev Sysfs Mount");

