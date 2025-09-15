
#include <kanawha/syscall.h>
#include <kanawha/proc/process.h>
#include <kanawha/proc/file_table.h>
#include <kanawha/fs/node.h>

#define SYSCALL_OPEN_MAX_PATH_LEN 256

#ifdef CONFIG_DEBUG_SYSCALL_OPEN
#define LOG(...)\
    printk(__VA_ARGS__)
#else
#define LOG(...)
#endif

int
syscall_open(
        const char __user *path,
        unsigned long access_flags,
        unsigned long mode_flags,
        fd_t __user *fd)
{
    int res;
    
    struct process *process = current_process();

    size_t path_len;
    res = process_strlen_usermem(process, path, SYSCALL_OPEN_MAX_PATH_LEN+1, &path_len);
    if(res) {
        return res;
    }

    if(path_len > SYSCALL_OPEN_MAX_PATH_LEN) {
        // Path is too long
        LOG("PID(%ld) syscall_open: path is too long! len=%llu, (>%llu)\n",
                (sl_t)process->id,
                (ull_t)path_len,
                (ull_t)SYSCALL_OPEN_MAX_PATH_LEN);
        return -EINVAL;
    }

    char path_buf[path_len + 1];

    res = process_read_usermem(
            process,
            (void*)path_buf,
            (void __user*)path,
            path_len);
    if(res) {
        LOG("syscall_open: failed to read file path! process_read_usermem(%p) -> %s\n",
                path, errnostr(res));
        return res;
    }

    path_buf[path_len] = '\0';

    LOG("PID(%ld) syscall_open(path=%s, path_len=0x%llx, access_flags=0x%llx, mode_flags=0x%llx)\n",
            process->id, path_buf, path_len, (ull_t)access_flags, (ull_t)mode_flags);

    struct fs_path *dir_path;
    if(mode_flags & FILE_MODE_OPEN_RELATIVE) {
	fd_t dir_fd;
	res = process_read_usermem(
		process,
		&dir_fd,
		fd,
		sizeof(dir_fd));
	if(res) {
	    return res;
	}
	struct file *dir_file;
	dir_file = file_table_get_file(
		process->file_table,
		process,
		dir_fd);

	dir_path = dir_file->path;
	fs_path_get(dir_path);

	file_table_put_file(
		process->file_table,
		process,
		dir_file);
    } else {
	int is_rel = 1;
	char *iter = path_buf;
	while(*iter) {
	    if(*iter == '/') {
		is_rel = 0;
		break;
	    } else if(*iter == ' ') {
		iter++;
	    } else {
		is_rel = 1;
		break;
	    }
	}
	if(is_rel) {
	    dir_path = process->working_directory;
	} else {
	    dir_path = process->root_directory;
	}
	fs_path_get(dir_path);
    }

    fd_t kernel_fd;
    res = file_table_open(
            process->file_table,
            process,
	    dir_path,
            path_buf,
            access_flags,
            mode_flags,
            &kernel_fd);
    if(res) {
        LOG("PID(%ld) syscall_open: file_table_open(%s) returned %s\n",
                (sl_t)process->id, path_buf, errnostr(res));
        return res;
    }

    fs_path_put(dir_path);

    res = process_write_usermem(
            process,
            fd,
            &kernel_fd,
            sizeof(fd_t));
    if(res) {
        file_table_close(process->file_table, process, kernel_fd);
        LOG("PID(%ld) syscall_open: Failed to write FID back to userspace!\n",
                (sl_t)process->id);
        return res;
    }

    if(mode_flags & FILE_MODE_OPEN_TRUNC) {
        struct file *file = file_table_get_file(
                process->file_table,
                process,
                kernel_fd);
        if(file == NULL) {
            LOG("PID(%ld) syscall_open: Failed to open file for truncation! (err=%s)\n",
                    process->id, errnostr(res));
            file_table_close(process->file_table, process, kernel_fd);
            return res;
        }

        struct fs_node *fs_node = fs_path_get_fs_node(file->path);
        if(fs_node == NULL) {
            file_table_put_file(process->file_table, process, file);
            file_table_close(process->file_table, process, kernel_fd);
            return -EINVAL;
        }

        res = fs_node_setattr(
                fs_node,
                FS_NODE_ATTR_DATA_SIZE,
                0);
        if(res) {
            LOG("PID(%ld) syscall_open: Failed to truncate file! (err=%s)\n",
                    process->id, errnostr(res));
            file_table_put_file(
                    process->file_table,
                    process,
                    file);
            file_table_close(process->file_table, process, kernel_fd);
            return res;
        }
    }

    LOG("PID(%ld) syscall_open: fd=%ld\n",
            (sl_t)process->id, (sl_t)kernel_fd);
    return 0;
}

