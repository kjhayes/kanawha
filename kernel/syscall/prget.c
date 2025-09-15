
#include <kanawha/syscall.h>
#include <kanawha/uapi/prinfo.h>

__attribute__((weak))
int
arch_prget(
	long field,
	unsigned long *value)
{
    return -EINVAL;
}

int
syscall_prget(
	unsigned long type,
	long field,
	unsigned long __user *user_value_ptr)
{
    int res;

    struct process *process = current_process();

    unsigned long value;
    switch(type) {
	case PRINFO_TYPE_ARCH:
	    res = arch_prget(field, &value);
	    if(res) {
	        return res;
	    }
	    res = process_write_usermem(
	    	process,
	    	user_value_ptr,
	    	&value,
	    	sizeof(unsigned long));
	    if(res) {
	        return res;
	    }
	    break;
	default:
	    return -EINVAL;
    }

    return 0;
}

