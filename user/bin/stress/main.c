#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define NUM_CHILDREN 1000 // Number of child processes to create

#define CHILD(...)
#define PARENT(...) printf(__VA_ARGS__)

void
child_process_task(int child_id)
{
    CHILD("Child %d (PID: %d) starting work...\n",
         (int)child_id,
         (int)getpid());
    // Simulate some work, e.g., CPU-bound computation, I/O operations, etc.
    // For a simple stress test, a loop can suffice.
    for(long long i = 0; i < 10000000ULL; ++i)
    {
        // Do some dummy calculations to keep the CPU busy
        volatile long result = i * i / (i + 1);
    }
    CHILD("Child %d (PID: %d) finished work.\n", (int)child_id, (int)getpid());
    exit(EXIT_SUCCESS); // Child process exits normally
}

int
main(int argc, const char **argv)
{
    pid_t pids[NUM_CHILDREN];
    int status;

    PARENT("Parent process (PID: %d) starting.\n", (int)getpid());

    // Forking multiple child processes
    for(int i = 0; i < NUM_CHILDREN; ++i)
    {
        PARENT("Launching Child %d\n", i);
        pids[i] = fork();

        if(pids[i] == -1)
        {
            perror("fork failed");
            exit(EXIT_FAILURE);
        }
        else if(pids[i] == 0)
        {
            // Child process
            child_process_task(i + 1); // Pass child ID
        }
    }

    // Parent waits for child processes to finish
    for(int i = 0; i < NUM_CHILDREN; ++i)
    {
        PARENT("Waiting for child %d\n", i);
        pid_t terminated_pid = waitpid(pids[i], &status, 0);

        if(terminated_pid == -1)
        {
            perror("waitpid failed");
        }
        else
        {
            if(WIFEXITED(status))
            {
                PARENT("Parent: Child %d (PID: %d) terminated "
                       "with exit status "
                       "%d.\n",
                       (int)i + 1,
                       (int)terminated_pid,
                       (int)WEXITSTATUS(status));
            }
            else if(WIFSIGNALED(status))
            {
                PARENT("Parent: Child %d (PID: %d) terminated by "
                       "signal %d.\n",
                       (int)i + 1,
                       (int)terminated_pid,
                       (int)WTERMSIG(status));
            }
        }
    }

    PARENT("Parent process (PID: %d) finished.\n", (int)getpid());
    return 0;
}
