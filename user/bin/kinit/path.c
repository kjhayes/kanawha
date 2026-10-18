
#include "path.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <elk/list.h>
#include <kanawha/mount.h>
#include <kanawha/syscall.h>
#include <kanawha/file.h>

#define KINIT_PATH_MOUNTPOINT (1UL<<0)
#define KINIT_PATH_ROOT (1UL<<1)
#define KINIT_PATH_REALIZED (1UL<<2)

struct kinit_path
{
    char *name;
    unsigned long flags;
    
    struct {
        char *source;
        char *fs_type;
        unsigned long flags;
    } mnt;

    struct kinit_path *parent;
    list_t children;
    list_node_t child_node;

    fd_t realized_fd;
};

DEFINE_CUSTOM_LIST(
        _kinit_path_children,
        struct kinit_path,
        children,
        struct kinit_path,
        child_node);

struct kinit_path *
_kinit_create_path(
        const char *name)
{
    struct kinit_path *p = malloc(sizeof(*p));
    if(p == NULL) {
        return NULL;
    }
    memset(p, 0, sizeof(*p));

    p->name = strdup(name);
    if(p->name == NULL) {
        free(p);
        return NULL;
    }

    p->mnt.source = NULL;
    p->mnt.fs_type = NULL;
    p->mnt.flags = 0;
    p->flags = 0;

    p->parent = NULL;
    _kinit_path_children_init(p);

    return p;
}

static inline void
_kinit_destroy_path(
        struct kinit_path *p)
{
    if(p->parent) {
        _kinit_path_children_remove(p->parent, p);
        p->parent = NULL;
    }
    free(p->mnt.source);
    free(p->mnt.fs_type);
    free(p->name);
    free(p);
}

struct kinit_path *
kinit_create_dir(
        const char *name)
{
    struct kinit_path *p = _kinit_create_path(name);
    if(p == NULL) {
        return NULL;
    }
    return p;
}

struct kinit_path *
kinit_create_mountpoint(
        const char *name,
        const char *source,
        const char *fs_type,
        unsigned long mount_flags
        )
{
    struct kinit_path *p = _kinit_create_path(name);
    if(p == NULL) {
        return NULL;
    }
    p->flags |= KINIT_PATH_MOUNTPOINT;
    p->mnt.source = strdup(source);
    p->mnt.fs_type = strdup(fs_type);
    p->mnt.flags = mount_flags;
    if(p->mnt.source == NULL || p->mnt.fs_type == NULL) {
        _kinit_destroy_path(p);
        return NULL;
    }
    return p;
}

int
kinit_path_append_child(
        struct kinit_path *parent,
        struct kinit_path *child)
{
    if(child->parent != NULL) {
        return -EALREADY;
    }
    _kinit_path_children_push_tail(parent, child);
    child->parent = parent;
    struct kinit_path *iter = child;
    while(iter) {
        iter->flags &= ~KINIT_PATH_REALIZED;
        iter = iter->parent;
        if(iter == child) {
            return -EINVAL;
        }
    }
    return 0;
}

static int
kinit_path_realized(struct kinit_path *path)
{
    if(path->parent) {
        return kinit_path_realized(path->parent);
    }
    return !!(path->flags & KINIT_PATH_REALIZED);
}

static int
_kinit_realize_path(
        struct kinit_path *path)
{
    int res;

    if(kinit_path_realized(path)) {
        return 0;
    }

    unsigned int close_parent_fd = 0;
    fd_t parent_fd;
    if(path->parent) {
        parent_fd = path->parent->realized_fd;
        close_parent_fd = 0;
    } else {
        res = kanawha_sys_open("", FILE_PERM_READ|FILE_PERM_WRITE, 0, &parent_fd);
        if(res) {
            return res;
        }
        close_parent_fd = 1;
    }

    if(path->parent) {
        // Make the directory (if it does not exist)
        do {
            fd_t dir_fd = parent_fd;
            res = kanawha_sys_open(path->name, FILE_PERM_READ, FILE_MODE_OPEN_RELATIVE, &dir_fd);
            if(res == 0) {
                // It exists already
                kanawha_sys_close(dir_fd);
                break;
            }

            // Create the directory
            res = kanawha_sys_mkdir(parent_fd, path->name, 0);
            if(res) {
                fprintf(stderr, "kinit: WARNING failed to create directory during path realization!\n");
                if(close_parent_fd) {
                    kanawha_sys_close(parent_fd);
                }
                return res;
            }
        } while(0);
    }

    if(path->flags & KINIT_PATH_MOUNTPOINT) {
        res = kanawha_sys_mount(
                path->mnt.source,
                parent_fd,
                path->name,
                path->mnt.fs_type,
                path->mnt.flags);
        if(res) {
            fprintf(stderr, "kinit: Failed to create mountpoint \"%s\" (src=\"%s\",fs=\"%s\")!\n",
                    path->name,
                    path->mnt.source,
                    path->mnt.fs_type);
            if(close_parent_fd) {
                kanawha_sys_close(parent_fd);
            }
            return res;
        }
    }

    fd_t self_fd = parent_fd;
    res = kanawha_sys_open(path->name, FILE_PERM_READ|FILE_PERM_WRITE, FILE_MODE_OPEN_RELATIVE, &self_fd);
    if(res) {
        fprintf(stderr, "kinit: Failed to open newly created mountpoint \"%s\"!\n",
                path->name);
        if(close_parent_fd) {
            kanawha_sys_close(parent_fd);
        }
        return res;
    }

    path->realized_fd = self_fd;

    if(path->flags & KINIT_PATH_ROOT) {
        res = kanawha_sys_chroot(path->realized_fd);
        if(res) {
            fprintf(stderr, "kinit_realize_path: failed to chroot!\n");
            return res;
        }
    }

    if(close_parent_fd) {
        res = kanawha_sys_close(parent_fd);
        if(res) {
            fprintf(stderr, "kinit: WARNING failed to close parent file descriptor when realizing path!\n");
        }
    }

    struct kinit_path *child_iter = _kinit_path_children_begin(path);
    while(child_iter) {
        res = _kinit_realize_path(child_iter);
        if(res) {
            return res;
        }
        child_iter = _kinit_path_children_next(path, child_iter);
    }

    path->flags |= KINIT_PATH_REALIZED;

    return 0;
}

static int
kinit_realize_path(
        struct kinit_path *path)
{
    if(path->parent && !kinit_path_realized(path->parent)) {
        return kinit_realize_path(path->parent);
    }
    return _kinit_realize_path(path);
}

static unsigned _kinit_root_active = 0;
static struct kinit_path * _kinit_root_path = NULL;

int
kinit_path_set_root(
        struct kinit_path *root)
{
    int res;
    struct kinit_path *old = _kinit_root_path;
    root->flags |= KINIT_PATH_ROOT;
    _kinit_root_path = root;
    if(old != NULL) {
        old->flags &= ~KINIT_PATH_ROOT;
    }
    res = kinit_realize_path(_kinit_root_path);
    if(res) {
        return res;
    }
    return 0;
}
struct kinit_path *
kinit_path_get_root(void)
{
    return _kinit_root_path;
}

int
kinit_activate_root_path(void)
{
    if(_kinit_root_active) {
        return 0;
    }
    _kinit_root_active = 1;
    if(_kinit_root_path) {
        return kinit_realize_path(_kinit_root_path);
    }
    return 0;
}

