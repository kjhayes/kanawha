
`close` syscall
===============

```C
int close(fd_t file);
```

# Overview
Closes the file descriptor `file`. This does not necessarily
immediately free the descriptor, as other processes attached
to the same file table could still have a reference.

`close` merely decrements the reference count on the descriptor
(initialized to 1 on `open`). When the reference count reaches
zero the descriptor will actually be freed.

# Arguments
`file`: index of the file descriptor to close.

# Return Value
Returns 0 on success, negative `errno` on failure.

