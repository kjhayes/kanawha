
#include <kanawha/uapi/syscall.h>
#include <kanawha/proc/file_table.h>
#include <kanawha/assert.h>
#include <kanawha/vmem.h>

int
syscall_fmove(
        struct process *process,
        fd_t dst,
        fd_t src,
        unsigned long flags)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(process));
    DEBUG_ASSERT(KERNEL_ADDR(process->file_table));

    dprintk("PID(%ld) fmove(dst=%ld, src=%ld, flags=0x%lx)\n",
            current_process()->id, dst, src, flags);

    switch(flags) {
      case FMOVE_SWAP:
        res = file_table_swap(
                process->file_table,
                dst,
                src);
        if(res) {
            return res;
        }
        break;
      case FMOVE_DUP:
        res = file_table_dup_into(
                process->file_table,
                dst,
                src);
        if(res) {
            return res;
        }
        break;
      default:
        return -EINVAL;
    }

    return 0;
}

