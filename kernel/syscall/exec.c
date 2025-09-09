
#include <kanawha/syscall.h>
#include <kanawha/proc/file_table.h>
#include <kanawha/proc/process.h>
#include <kanawha/types.h>
#include <kanawha/stddef.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/assert.h>
#include <kanawha/uapi/mmap.h>
#include <kanawha/uapi/exec.h>
#include <kanawha/proc/mmap.h>
#include <kanawha/fs/node.h>
#include <kanawha/exec_type.h>

#ifdef CONFIG_DEBUG_SYSCALL_EXEC
#define LOG(fmt, ...) printk("PID(%ld) syscall_exec: " fmt, process->id, ##__VA_ARGS__)
#else
#define LOG(...)
#endif

struct exec_probe_state
{
    int status;
    struct exec_type *type;

    // Used for probing different executable formats
    struct process *process;
    struct file *file;
};

static void
exec_syscall_exec_type_probe_callback(
	struct exec_type *exec_type,
	void *state_opaque_ptr)
{
    struct exec_probe_state *state = state_opaque_ptr;

    if(state->status == EXEC_TYPE_PROBE_CLAIM || state->status < 0) {
	// Some other exec_type claimed this file or threw an error
	return;
    }

    int res;
    res = exec_type_probe(exec_type, state->process, state->file);
    if(res < 0) {
	state->status = res;
	return;
    }

    if(res == EXEC_TYPE_PROBE_MAYBE && state->status == EXEC_TYPE_PROBE_REJECT) {
	state->type = exec_type;
	state->status = EXEC_TYPE_PROBE_MAYBE;
    }
    else if(res == EXEC_TYPE_PROBE_CLAIM) {
	state->type = exec_type;
	state->status = EXEC_TYPE_PROBE_CLAIM;
    }
    else {
        DEBUG_ASSERT(res == EXEC_TYPE_PROBE_REJECT);
    }
}

int
syscall_exec(
        struct process *process,
        fd_t file,
        unsigned long exec_flags)
{
    int res;

    struct file *desc =
        file_table_get_file(process->file_table, process, file);

    const char *name = fs_path_get_name(desc->path);
    LOG("exec(%ld) %s\n",
            file,
            desc == NULL ? "NULL" : name == NULL ? "UNNAMED" : name);

    if(desc == NULL) {
        file_table_put_file(process->file_table, process, desc);
        return -EINVAL;
    }

    if((desc->access_flags & FILE_PERM_EXEC) == 0) {
        file_table_put_file(process->file_table, process, desc);
        eprintk("syscall_exec: file does not have EXEC permissions! (path->name=\"%s\")\n",
                name);
        return -EPERM;
    }

    struct exec_probe_state probe_state = {
	.status = EXEC_TYPE_PROBE_REJECT,
	.type = NULL,

	.process = process,
	.file = desc,
    };
 
    for_each_exec_type(
	    exec_syscall_exec_type_probe_callback,
	    &probe_state);

    if(probe_state.status < 0) {
	file_table_put_file(process->file_table, process, desc);
	return probe_state.status;
    }
    else if(probe_state.status == EXEC_TYPE_PROBE_REJECT) {
	file_table_put_file(process->file_table, process, desc);
	return -EINVAL;
    }
    else if((probe_state.status == EXEC_TYPE_PROBE_MAYBE) && !(exec_flags & EXEC_PERMISSIVE)) {
	file_table_put_file(process->file_table, process, desc);
	return -EINVAL;
    }

    DEBUG_ASSERT(KERNEL_ADDR(probe_state.type));

    res = mmap_deattach(process->mmap, process);
    if(res) {
        file_table_put_file(process->file_table, process, desc);
        eprintk("syscall_exec: Failed to deattach mmap! (err=%s)\n",
                errnostr(res));
        return res;
    }

    res = mmap_create(PROCESS_LOWMEM_SIZE, process);
    if(res) {
        file_table_put_file(process->file_table, process, desc);
        eprintk("syscall_exec: Failed to create new mmap! (err=%s)\n",
                errnostr(res));
        return res;
    }

    res = exec_type_load(probe_state.type, process, desc);
    if(res) {
        file_table_put_file(process->file_table, process, desc);
        return res;
    }

#ifdef CONFIG_DEBUG_TRACK_PROCESS_EXEC
    if(process->tracked_exec) {
        kfree((void*)process->tracked_exec);
    }
    if(name) {
        process->tracked_exec = kstrdup(name);
    }
#endif

    dprintk("syscall_exec: desc->path->fs_node->index = %lld\n", (sll_t)desc->path->fs_node->cache_node.key);
    file_table_put_file(process->file_table, process, desc);

    res = file_table_on_exec(process->file_table, process);
    if(res) {
	wprintk("syscall_exec: Failed to handle CLOSE_ON_EXEC files! (err=%s)\n",
		errnostr(res));
    }

    res = vmem_flush_region(process->mmap->vmem_region);
    if(res) {
        eprintk("syscall_exec: Failed to flush mmap region!\n");
        return res;
    }

    return 0;
}


