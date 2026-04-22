#include <kanawha/cpu.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/type.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/lock.h>
#include <kanawha/page_alloc.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/sysfs/sysfs.h>
#include <kanawha/sysfs/vfs.h>
#include <kanawha/types.h>

struct cpu_fs_node
{
    struct cpu *cpu;
    struct vfs_node vfs_node;

    struct vfs_node id_node;
    struct vfs_node bsp_node;
    struct vfs_node idle_node;
};

static struct vfs_mount *cpu_fs_mount = NULL;

static struct fs_node_ops cpu_fs_node_ops;
static struct fs_file_ops cpu_fs_file_ops;

static struct fs_node_ops id_node_ops;
static struct fs_file_ops id_file_ops;

static struct fs_node_ops bsp_node_ops;
static struct fs_file_ops bsp_file_ops;

static struct fs_node_ops idle_node_ops;
static struct fs_file_ops idle_file_ops;

static int
cpu_fs_probe_cpu(struct cpu *cpu)
{
    return 0;
}

static int
cpu_fs_receive_cpu(struct cpu *cpu)
{
    int res;
    struct cpu_fs_node *node = kmalloc(sizeof(*node), KM_KERNEL);
    if(node == NULL)
    {
        res = -ENOMEM;
        goto err0;
    }
    node->cpu = cpu;

    node->vfs_node.fs_node_ops = &cpu_fs_node_ops;
    node->vfs_node.fs_file_ops = &cpu_fs_file_ops;
    res = vfs_mount_insert_node_and_link_root(cpu_fs_mount,
                                              &node->vfs_node,
                                              cpu_get_name(cpu));
    if(res)
    {
        goto err1;
    }

    node->id_node.fs_node_ops = &id_node_ops;
    node->id_node.fs_file_ops = &id_file_ops;
    res = vfs_mount_insert_and_link(cpu_fs_mount,
                                    &node->id_node,
                                    "id",
                                    &node->vfs_node);
    if(res)
    {
        goto err2;
    }

    node->bsp_node.fs_node_ops = &bsp_node_ops;
    node->bsp_node.fs_file_ops = &bsp_file_ops;
    res = vfs_mount_insert_and_link(cpu_fs_mount,
                                    &node->bsp_node,
                                    "bsp",
                                    &node->vfs_node);
    if(res)
    {
        goto err3;
    }

    node->idle_node.fs_node_ops = &idle_node_ops;
    node->idle_node.fs_file_ops = &idle_file_ops;
    res = vfs_mount_insert_and_link(cpu_fs_mount,
                                    &node->idle_node,
                                    "idle",
                                    &node->vfs_node);
    if(res)
    {
        goto err4;
    }

    return 0;

err4:
    vfs_mount_remove_node(cpu_fs_mount, &node->bsp_node);
err3:
    vfs_mount_remove_node(cpu_fs_mount, &node->id_node);
err2:
    vfs_mount_unlink_root(cpu_fs_mount, cpu_get_name(cpu));
    vfs_mount_remove_node(cpu_fs_mount, &node->vfs_node);
err1:
    kfree(node);
err0:
    return res;
}

static int
cpu_fs_revoke_cpu(struct cpu *cpu)
{
    eprintk("Tried to unregister cpu from cpu sysfs! (UNIMPL)\n");
    return -EUNIMPL;
}

static struct cpu_owner cpu_sysfs_owner = {
    .probe = cpu_fs_probe_cpu,
    .receive = cpu_fs_receive_cpu,
    .revoke = cpu_fs_revoke_cpu,
};

static int
cpu_init_fs_mount(void)
{
    int res;

    struct vfs_mount *mnt;
    mnt = vfs_mount_create();
    if(mnt == NULL)
    {
        eprintk("Failed to create cpu VFS mount!\n");
        return -ENOMEM;
    }

    cpu_fs_mount = mnt;

    res = register_cpu_owner(&cpu_sysfs_owner);
    if(res)
    {
        vfs_mount_destroy(mnt);
        return res;
    }

    res = sysfs_register_mount(&cpu_fs_mount->fs_mount, "cpu");
    if(res)
    {
        cpu_fs_mount = NULL;
        vfs_mount_destroy(mnt);
        unregister_cpu_owner(&cpu_sysfs_owner);
        return res;
    }

    return 0;
}
declare_init_desc(fs, cpu_init_fs_mount, "Registering cpu Sysfs Mount");

// Main "cpu" Node

static struct fs_node_ops cpu_fs_node_ops = {
    .lookup = vfs_dir_lookup,
};
FS_NODE_OPS_INIT_UNDEF(cpu_fs_node_ops);

static struct fs_file_ops cpu_fs_file_ops = {
    .seek = fs_file_seek_pinned_zero,
    .flush = fs_file_nop_flush,

    .dir_begin = vfs_dir_begin,
    .dir_next = vfs_dir_next,
    .dir_readattr = vfs_dir_readattr,
    .dir_readname = vfs_dir_readname,
};
FS_FILE_OPS_INIT_UNDEF(cpu_fs_file_ops);

// "id" Node

static ssize_t
id_file_read(struct file *file,
             void *buffer,
             ssize_t buflen,
             unsigned long flags)
{
    if(file->seek_offset != 0)
    {
        return 0;
    }

    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    struct cpu_fs_node *cpu_node =
        container_of(fs_node->backing.priv_state, struct cpu_fs_node, id_node);

    snprintk(buffer, buflen, "%ld", (sl_t)cpu_node->cpu->id);
    size_t len = strnlen(buffer, buflen);

    return len;
}

static struct fs_node_ops id_node_ops = {};
FS_NODE_OPS_INIT_UNDEF(id_node_ops);
static struct fs_file_ops id_file_ops = {
    .seek = fs_file_seek_pinned_zero,
    .flush = fs_file_nop_flush,

    .read = id_file_read,
};
FS_FILE_OPS_INIT_UNDEF(id_file_ops);

// "bsp" Node

static ssize_t
bsp_file_read(struct file *file,
              void *buffer,
              ssize_t buflen,
              unsigned long flags)
{
    if(file->seek_offset != 0)
    {
        return 0;
    }

    if(buflen == 0)
    {
        return -EINVAL;
    }

    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    struct cpu_fs_node *cpu_node =
        container_of(fs_node->backing.priv_state, struct cpu_fs_node, bsp_node);

    if(cpu_node->cpu->flags & CPU_FLAG_IS_BSP)
    {
        *(char *)buffer = '1';
    }
    else
    {
        *(char *)buffer = '0';
    }
    return 1;
}

static struct fs_node_ops bsp_node_ops = {};
FS_NODE_OPS_INIT_UNDEF(bsp_node_ops);
static struct fs_file_ops bsp_file_ops = {
    .seek = fs_file_seek_pinned_zero,
    .flush = fs_file_nop_flush,

    .read = bsp_file_read,
};
FS_FILE_OPS_INIT_UNDEF(bsp_file_ops);

// "idle" Node

static ssize_t
idle_file_read(struct file *file,
               void *buffer,
               ssize_t buflen,
               unsigned long flags)
{
    if(file->seek_offset != 0)
    {
        return 0;
    }

    if(buflen == 0)
    {
        return -EINVAL;
    }

    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    struct cpu_fs_node *cpu_node = container_of(fs_node->backing.priv_state,
                                                struct cpu_fs_node,
                                                idle_node);

    ssize_t idle_percent = cpu_idle_percentage(cpu_node->cpu->id);
    if(idle_percent < 0)
    {
        wprintk("cpufs: failed to read CPU(%ld) idle percentage! (err=%s)\n",
                (sl_t)cpu_node->cpu->id,
                errnostr(idle_percent));
        return idle_percent;
    }

    snprintk(buffer, buflen, "%d", (int)idle_percent);
    size_t len = strnlen(buffer, buflen);

    return len;
}

static struct fs_node_ops idle_node_ops = {};
FS_NODE_OPS_INIT_UNDEF(idle_node_ops);
static struct fs_file_ops idle_file_ops = {
    .seek = fs_file_seek_pinned_zero,
    .flush = fs_file_nop_flush,

    .read = idle_file_read,
};
FS_FILE_OPS_INIT_UNDEF(idle_file_ops);
