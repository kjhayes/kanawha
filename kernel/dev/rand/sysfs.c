
#include <kanawha/dev/rand.h>
#include <kanawha/fs/mount.h>
#include <kanawha/sysfs/vfs.h>
#include <kanawha/sysfs/sysfs.h>
#include <kanawha/init.h>
#include <kanawha/lock.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>

struct rand_dev_fs_node {
    struct vfs_node vfs_node;
    struct rand_dev *dev;
};

static struct vfs_mount *rand_dev_fs_mount = NULL;

static ssize_t 
rand_dev_fs_file_read(
        struct file *file,
        void * buf,
        ssize_t buflen,
        unsigned long flags
        )
{
    int res;

    struct fs_node *node = fs_path_get_fs_node(file->path);
    if(node == NULL) {
        return -ENXIO;
    }
    struct rand_dev_fs_node *rdfs =
        container_of(node->backing.priv_state, struct rand_dev_fs_node, vfs_node);

    if(buflen <= 0) {
        return -EINVAL;
    }

    ssize_t amt_read;
    while(1) {
        amt_read = rand_dev_read(
		rdfs->dev,
            	buf,
            	buflen);
	    if(amt_read < 0) {
	        if(amt_read == -EWOULDBLOCK && !(flags & FS_FILE_READ_NON_BLOCKING)) {
	    	    res = wait_on(&rdfs->dev->read_wq);
                if(res) {
                    return res;
                }
	    	    continue;
	        } else {
	    	    return amt_read;
	        }
	    }
	    break;
    }

    return amt_read;
}

static struct fs_node_ops rand_dev_fs_node_ops = {
    .lookup = vfs_dir_lookup,
};
FS_NODE_OPS_INIT_UNDEF(rand_dev_fs_node_ops);

static struct fs_file_ops rand_dev_fs_file_ops =
{
    .dir_begin = vfs_dir_begin,
    .dir_next = vfs_dir_next,
    .dir_readattr = vfs_dir_readattr,
    .dir_readname = vfs_dir_readname,

    .read = rand_dev_fs_file_read,
};
FS_FILE_OPS_INIT_UNDEF(rand_dev_fs_file_ops);

static int
rand_dev_fs_probe_rand_dev(
        struct rand_dev *dev)
{
    return 0;
}

static int
rand_dev_fs_receive_rand_dev(
        struct rand_dev *dev)
{
    int res;

    struct rand_dev_fs_node *rdfs = kmalloc(sizeof(*rdfs), KM_KERNEL);
    if(rdfs == NULL) {
        return -ENOMEM;
    }
    memset(rdfs, 0, sizeof(*rdfs));

    rdfs->dev = dev;

    rdfs->vfs_node.fs_node_ops = &rand_dev_fs_node_ops;
    rdfs->vfs_node.fs_file_ops = &rand_dev_fs_file_ops;

    size_t inode;

    res = vfs_mount_insert_node(
            rand_dev_fs_mount,
            &rdfs->vfs_node,
            &inode);
    if(res) {
        kfree(rdfs);
        return res;
    }

    res = vfs_mount_link_root(
            rand_dev_fs_mount,
            rand_dev_get_name(dev),
            inode);
    if(res) {
        vfs_mount_remove_node(
                rand_dev_fs_mount,
                &rdfs->vfs_node);
        kfree(rdfs);
        return res;
    }

    return 0;
}

static int
rand_dev_fs_revoke_rand_dev(
        struct rand_dev *dev)
{
    wprintk("Tried to unregister a rand_dev from sysfs! (UNIMPL)\n");
    return -EUNIMPL;
}

static struct rand_dev_owner
rand_dev_fs_owner = {
    .probe = rand_dev_fs_probe_rand_dev,
    .receive = rand_dev_fs_receive_rand_dev,
    .revoke = rand_dev_fs_revoke_rand_dev,
};

static int
rand_dev_init_fs_mount(void)
{
    int res;
    struct vfs_mount *mnt;
    mnt = vfs_mount_create();
    if(mnt == NULL) {
        eprintk("Failed to create VFS mount for sysfs framebuffers!\n");
        return -ENOMEM;
    }

    rand_dev_fs_mount = mnt;

    res = register_rand_dev_owner(&rand_dev_fs_owner);
    if(res) {
        vfs_mount_destroy(mnt);
        return res;
    }

    res = sysfs_register_mount(
            &rand_dev_fs_mount->fs_mount,
            "randdev");
    if(res) {
        unregister_rand_dev_owner(&rand_dev_fs_owner);
        vfs_mount_destroy(mnt);
        return -ENOMEM;
    }

    return 0;
}

declare_init_desc(fs, rand_dev_init_fs_mount, "Registering randdev Sysfs Mount");
