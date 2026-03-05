
#include <kanawha/assert.h>
#include <kanawha/proc/file_table.h>
#include <kanawha/uapi/syscall.h>
#include <kanawha/usermode.h>
#include <kanawha/vmem.h>

int
syscall_fmove(fd_t dst, fd_t src, unsigned long flags, fd_t __user *user_out)
{
    int res;

    struct process *process = current_process();

    DEBUG_ASSERT(KERNEL_ADDR(process));
    DEBUG_ASSERT(KERNEL_ADDR(process->file_table));

    fd_t out;

    dprintk("PID(%ld) fmove(dst=%ld, src=%ld, flags=0x%lx)\n",
            current_process()->id,
            dst,
            src,
            flags);

    switch(flags)
    {
    case FMOVE_SWAP:
        res = file_table_swap(process->file_table, dst, src);
        if(res)
        {
            return res;
        }
        break;
    case FMOVE_DUP:
        res = file_table_dup_into(process->file_table, dst, src, &out);
        if(res)
        {
            return res;
        }
        if(user_out != NULL)
        {
            res = process_write_usermem(process, user_out, &out, sizeof(fd_t));
            if(res)
            {
                return res;
            }
        }
        break;
    default:
        return -EINVAL;
    }

    return 0;
}
