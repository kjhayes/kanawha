`exit` syscall
==============

```C
void exit(int exitcode);
```

Terminates the calling process with `exitcode` being returned to the parent process through `reap`.

