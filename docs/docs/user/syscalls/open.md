
`open` syscall
==============

```C
int open(const char *path, unsigned long access_flags, unsigned long mode_flags, fd_t *fd);
```

# Overview
Opens a new file descriptor within the calling process' file table.

# Arguments
`path`: pointer to a `NULL` terminated string containing
the file path to open.

`access_flags`: the bitwise-or of zero or more of the following macros defined in `uapi/file.h`.

- `FILE_PERM_READ`: the file descriptor should be readable.
- `FILE_PERM_WRITE`: the file descriptor should be writeable.
- `FILE_PERM_EXEC`: the file descriptor should be executable.

`mode_flags`: the bitwise-or of zero or more of the following macros defined in `uapi/file.h`.

- `FILE_MODE_WRITE_EXTEND`: if a write to this descriptor would go beyond the end of the file, attempt to grow the file to allow the write to succeed.
- `FILE_MODE_OPEN_TRUNC`: attempt to set the length of the file to zero before opening.
- `FILE_MODE_NON_BLOCK`: accesses (`read`/`write`/etc.) to this file should be non-blocking. That is, if an access would block, instead return `-EWOULDBLOCK` immediately.

`fd`: pointer to a `fd_t` to write the newly opened file descriptor index into on success.

# Return Value
Returns 0 on success, a negative `errno` on failure.

