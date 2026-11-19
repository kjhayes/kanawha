
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "timing.h"

#ifdef FORK_TEST_LOUD
#define PRINT(fmt, ...)\
    printf(fmt, ##__VA_ARGS__)
#define CHILD_PRINT(fmt, ...)\
    printf(fmt, ##__VA_ARGS__)
#define PARENT_PRINT(fmt, ...)\
    printf(fmt, ##__VA_ARGS__)
#else
#define PRINT(fmt, ...)
#define CHILD_PRINT(fmt, ...)
#define PARENT_PRINT(fmt, ...)
#endif

int fork_main(int argc, const char **argv)
{
    int res;
    int depth_limit = 1000;
    int fork_depth = 0;

    elapse_t total_elapsed;

    printf("Starting Fork Test (Max. Depth = %d)\n", depth_limit);

    elapse_begin(&total_elapsed);

    while(fork_depth < depth_limit) {
        int child_id = fork();
        int child_depth = fork_depth+1;
        if(child_id == 0) {
            fork_depth = child_depth;
            // We are the child
            // Continue "Looping"
            CHILD_PRINT("PID(%d) Child at depth %d\n", getpid(), fork_depth);
            continue;
        } else {
            // We are the parent
            int result;
            PARENT_PRINT("PID(%d) Parent Waiting For Child %d (depth=%d)\n", getpid(), child_id, child_depth);
            while(waitpid(child_id, &result, 0) != child_id) {}
            PARENT_PRINT("PID(%d) Parent Reaped Child %d\n", getpid(), child_id);
            if(result != 0) {
                return result;
            }
            // Do not continue looping,
            // loop iteration should really
            // correspond to "child" depth
            break;
        }
    }
    if(fork_depth != 0) {
        // Child exit
        return 0;
    }

    elapse_end(&total_elapsed);

    // We are the original root
    printf("Fork Test Complete (");
    print_elapsed_sec(stdout, &total_elapsed);
    printf(" sec)\n");
    return 0;
}

