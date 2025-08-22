#ifndef __KANAWHA__DEV_TERM_SYSFS_H__
#define __KANAWHA__DEV_TERM_SYSFS_H__

#include <kanawha/dev/term.h>
#include <kanawha/sysfs/sysfs.h>
#include <kanawha/sysfs/vfs.h>

struct term_dev_fs_node
{
    struct term_dev *dev;

    struct vfs_node stream_vfs_node;
    struct vfs_node baudrate_vfs_node;
    struct vfs_node raw_vfs_node;
};

extern struct vfs_mount *term_dev_fs_mount;

#define  term_dev_from_node(__node, __field)\
({\
    struct term_dev_fs_node *tdfs =\
	container_of(\
		(struct vfs_node*)__node->backing.priv_state,\
		struct term_dev_fs_node,\
		__field);\
    struct term_dev *dev = tdfs->dev;\
    dev;\
})

#define term_dev_from_file(__file, __field)\
({\
    struct fs_node *fs_node = fs_path_get_fs_node(__file->path);\
    struct term_dev *dev;\
    if(fs_node == NULL)\
    {\
	dev = NULL;\
    } else {\
        dev = term_dev_from_node(fs_node, __field);\
    }\
    dev;\
})

extern int term_dev_fs_node_init_stream(struct term_dev_fs_node *node);
extern int term_dev_fs_node_deinit_stream(struct term_dev_fs_node *node);

extern int term_dev_fs_node_init_baudrate(struct term_dev_fs_node *node);
extern int term_dev_fs_node_deinit_baudrate(struct term_dev_fs_node *node);

extern int term_dev_fs_node_init_raw(struct term_dev_fs_node *node);
extern int term_dev_fs_node_deinit_raw(struct term_dev_fs_node *node);

#endif
