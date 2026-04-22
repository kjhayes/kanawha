`exit` syscall
==============

```C
void exit(int exitcode);
```

# Overview
Terminates the calling process.

# Arguments
`exitcode`: status code to be returned
to the parent process when `reap` is called.

# Return Value
The `exit` system call cannot return.

