
#include <kanawha/mount.h>
#include <kanawha/sys-wrappers.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dir.h"
#include "log.h"

static int
setup_ramfs(void)
{
    int res;
    fd_t cur_dir;
    res = kanawha_sys_open("", FILE_PERM_READ, 0, &cur_dir);
    if(res)
    {
        return res;
    }
    res = kanawha_sys_mount("ramfs", cur_dir, "root", "ramfs", MOUNT_SPECIAL);
    if(res)
    {
        return res;
    }
    kanawha_sys_close(cur_dir);
    res = kanawha_sys_open("root", FILE_PERM_READ, 0, &cur_dir);
    if(res)
    {
        return res;
    }
    res = kanawha_sys_chroot(cur_dir);
    if(res)
    {
        return res;
    }
    res = kanawha_sys_chwdir(cur_dir);
    if(res)
    {
        return res;
    }
    kanawha_sys_close(cur_dir);
    return 0;
}

struct sysfs_mnt
{
    const char *dir;
    const char *sysfs;
};

const static struct sysfs_mnt dev_sysfs_mnts[] = {
    {
        .dir = "term",
        .sysfs = "termdev",
    },
    {
        .dir = "input",
        .sysfs = "inputdev",
    },
    {
        .dir = "fb",
        .sysfs = "fbdev",
    },
    {
        .dir = "rand",
        .sysfs = "randdev",
    },
    {
        .dir = "blk",
        .sysfs = "blkdev",
    },
    {
        .dir = "snd",
        .sysfs = "snddev",
    },
    {
        .dir = "eth",
        .sysfs = "ethdev",
    },
    {
        .dir = "ipv4",
        .sysfs = "ipv4dev",
    },
    {
        .dir = "ramfile",
        .sysfs = "ramfile",
    },
    {
        .dir = "pty",
        .sysfs = "pty",
    },
};

const static struct sysfs_mnt sys_sysfs_mnts[] = {
    {
        .dir = "info",
        .sysfs = "info",
    },
    {
        .dir = "pci",
        .sysfs = "pci",
    },
    {
        .dir = "acpi",
        .sysfs = "acpi",
    },
    {
        .dir = "proc",
        .sysfs = "proc",
    },
    {
        .dir = "udrv",
        .sysfs = "udrv",
    },
    {
        .dir = "cpu",
        .sysfs = "cpu",
    },
};

struct fs_mnt
{
    const char *backing;
    const char *fs_type;
    const char *dir;
};

const static struct fs_mnt sys_base_fs_mnts[] = {
    {
#ifdef __aarch64__
        .backing = "/dev/blk/virtio-blk-0",
#else
        .backing = "/dev/ramfile/initrd",
#endif
        .fs_type = "cpio",
        .dir = "initrd",
    },
};

static int
setup_sysfs_mounts(const char *dir, struct sysfs_mnt *mnts, size_t num_mnts)
{
    int res;

    int dir_fd;
    res = kanawha_sys_open(dir, FILE_PERM_WRITE, 0, &dir_fd);
    if(res)
    {
        return res;
    }

    for(size_t i = 0; i < num_mnts; i++)
    {
        struct sysfs_mnt *mnt = &mnts[i];
        res = kanawha_sys_mkdir(dir_fd, mnt->dir, 0);
        if(res)
        {
            return res;
        }
        res = kanawha_sys_mount(mnt->sysfs,
                                dir_fd,
                                mnt->dir,
                                "sys",
                                MOUNT_SPECIAL);
        if(res)
        {
            return res;
        }
    }

    kanawha_sys_close(dir_fd);

    return 0;
}

static int
setup_fs_mounts(const char *dir, struct fs_mnt *mnts, size_t num_mnts)
{
    int res;

    int dir_fd;
    res = kanawha_sys_open(dir, FILE_PERM_WRITE, 0, &dir_fd);
    if(res)
    {
        return res;
    }

    for(size_t i = 0; i < num_mnts; i++)
    {
        struct fs_mnt *mnt = &mnts[i];
        res = kanawha_sys_mkdir(dir_fd, mnt->dir, 0);
        if(res)
        {
            return res;
        }
        res = kanawha_sys_mount(mnt->backing,
                                dir_fd,
                                mnt->dir,
                                mnt->fs_type,
                                MOUNT_FILE);
        if(res)
        {
            return res;
        }
    }

    kanawha_sys_close(dir_fd);

    return 0;
}

int
setup_root_fs(void)
{
    int res;
    res = setup_ramfs();
    if(res)
    {
        return res;
    }

    {
        res = mkdir("dev", 0);
        if(res)
        {
            return res;
        }
        res = setup_sysfs_mounts("dev",
                                 (struct sysfs_mnt *)dev_sysfs_mnts,
                                 sizeof(dev_sysfs_mnts) /
                                     sizeof(dev_sysfs_mnts[0]));
        if(res)
        {
            return res;
        }
    }

    INFO("setup /dev filesystem\n");

    {
        res = mkdir("sys", 0);
        if(res)
        {
            return res;
        }
        res = setup_sysfs_mounts("sys",
                                 (struct sysfs_mnt *)sys_sysfs_mnts,
                                 sizeof(sys_sysfs_mnts) /
                                     sizeof(sys_sysfs_mnts[0]));
        if(res)
        {
            return res;
        }
        res = setup_fs_mounts("sys",
                              (struct fs_mnt *)sys_base_fs_mnts,
                              sizeof(sys_base_fs_mnts) /
                                  sizeof(sys_base_fs_mnts[0]));
        if(res)
        {
            return res;
        }
    }

    INFO("setup /sys filesystem\n");
}
