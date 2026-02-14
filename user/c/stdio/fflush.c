
#include "kanawha/sys-wrappers.h"
#include "elk-libc-internal/__sFILE.h"

#include <stdio.h>

#undef fflush_unlocked
int
fflush_unlocked(FILE *stream)
{
    int res;

    res = kanawha_sys_flush(
            stream->__fd,
            0);
    if(res) {
        return res;
    }

    return 0;
}

#undef fflush
int
fflush(FILE *stream)
{
    int res;

    if(stream == NULL) {
	// TODO: Technically this should flush all files
	//       But for now this seems to be good enough
	if(stdin != NULL) {
	    fflush(stdin);
	}
	if(stdout != NULL) {
	    fflush(stdout);
	}
	if(stderr != NULL) {
	    fflush(stderr);
	}
	return 0;
    }

    flockfile(stream);
    res = fflush_unlocked(stream);
    funlockfile(stream);
    return res;
}

