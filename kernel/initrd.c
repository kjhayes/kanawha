
#include <kanawha/blk_dev.h>
#include <kanawha/init.h>
#include <kanawha/file.h>
#include <kanawha/fs.h>
#include <kanawha/vmem.h>
#include <kanawha/string.h>
#include <kanawha/kmalloc.h>
#include <kanawha/module.h>
#include <kanawha/assert.h>

//static int
//handle_initrd_module(const char *path)
//{
//    int res;
//    struct file *file = file_open(path);
//    if(file == NULL) {
//        eprintk("Could not find initrd module file: \"%s\"\n",
//                path);
//        return -ENXIO;
//    }
//
//    printk("Found initrd module file: \"%s\"\n", path);
//    struct module *mod = load_module(file);
//    if(mod == NULL) {
//        eprintk("Failed to load initrd module: \"%s\"\n", path);
//        res = file_close(file);
//        if(res) {
//            eprintk("Failed to close file during error!\n");
//        }
//        return res;
//    }
//
//    res = file_close(file);
//    if(res) {
//        eprintk("Failed to close initrd module file: \"%s\" (err=%s)\n",
//                path, errnostr(res));
//        return res;
//    }
//    return 0;
//}
//
static int
mount_initrd(void)
{
    int res;

//    struct fs_mount *mnt;
//    struct fs_node *backing_node;
//
//    struct blk_dev *dev = fs_path_lookup(CONFIG_INITRD_RAMFILE_PATH);
//    if(dev == NULL) {
//        eprintk("Could not find initrd blk_dev \"%s\"!\n", CONFIG_INITRD_BLK_DEV);
//        return -ENXIO;
//    }
//
//    struct fs_type *type = fs_type_find(CONFIG_INITRD_FS_NAME);
//    if(type == NULL) {
//        eprintk("Could not find initrd filesystem type \"%s\"!\n", CONFIG_INITRD_FS_NAME);
//        return -ENXIO;
//    }
//
//    struct fs_mount *mnt;
//    res = fs_type_mount_file(
//            type,
//            dev,
//            CONFIG_INITRD_DISK,
//            &mnt);
//    if(res) {
//        eprintk("Failed to create filesystem mount for initrd! (err=%s)\n",
//                errnostr(res));
//        return res;
//    }
//
//    // Mount it as the default
//    res = fs_attach_mount(mnt, "");
//    if(res) {
//        eprintk("Failed to attach initrd filesystem mount! (err=%s)\n",
//                errnostr(res));
//        return res;
//    }
//
//    struct file *index = file_open(CONFIG_INITRD_INDEX_PATH);
//    if(index == NULL) {
//        eprintk("Failed to find initrd index file using path: \"%s\"\n",
//                CONFIG_INITRD_INDEX_PATH);
//        return -ENXIO;
//    }
//
//    file_seek(index, 0, FILE_SEEK_END);
//    size_t file_size = file_tell(index);
//
//    file_seek(index, 0, FILE_SEEK_ABS);
//
//    // Just load the entire file
//    // This is not efficient but it's simple
//    char *buffer = kmalloc(file_size+1);
//    if(buffer == NULL) {
//        eprintk("Failed to allocate index file buffer!\n");
//        return -ENOMEM;
//    }
//    buffer[file_size] = '\0';
//    size_t read = file_read(index, buffer, file_size);
//    if(read != file_size) {
//        eprintk("Failed to read the entire initrd index file (size=0x%lx, read=0x%lx)!\n",
//                (unsigned long)file_size, (unsigned long)read);
//        DEBUG_ASSERT(read <= file_size);
//    }
//    buffer[read] = '\0';
//
//    // Set all whitespace to NULL-terminators
//    for(size_t i = 0; i < read; i++) {
//        switch(buffer[i]) {
//            case ' ':
//            case '\t':
//            case '\r':
//            case '\n':
//                buffer[i] = '\0';
//                break;
//        }
//    }
//
//    size_t i = 0;
//    res = 0;
//    size_t num_loaded = 0;
//    while(i < read) {
//        char *cur = buffer + i;
//        size_t len = strlen(cur);
//        if(len != 0) {
//            res = handle_initrd_module(cur);
//            if(res) {
//                break;
//            }
//            num_loaded += 1;
//        }
//        i += (len+1);
//    }
//
//    kfree(buffer);
//
//    if(res) {
//        eprintk("initrd failed to load module! (quitting loading early) (err=%s)\n", errnostr(res));
//    }
//
//    printk("Loaded %ld initrd modules!\n", num_loaded);
//
//    res = file_close(index);
//    if(res) {
//        eprintk("Failed to close initrd index file! (err=%s)\n", errnostr(res));
//        return res;
//    }
    return 0;
}

declare_init_desc(late, mount_initrd, "Mounting initrd Filesystem");

