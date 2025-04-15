
`open` syscall
==============

```C
int open(const char __user *path, unsigned long access_flags, unsigned long mode_flags, fd_t __user *fd);
```

Open `path` and return the newly created file descriptor through `fd`.

Returns 0 on success, a negative `errno` on failure.

`access_flags` is the bitwise-or of zero or more of the following macros defined in `uapi/file.h`.

- `FILE_PERM_READ`
- `FILE_PERM_WRITE`
- `FILE_PERM_EXEC`

`mode_flags` is the bitwise-or of zero or more of the following macros defined in `uapi/file.h`.

- `FILE_MODE_WRITE_EXTEND`
- `FILE_MODE_OPEN_TRUNC`
- `FILE_MODE_NON_BLOCK`

