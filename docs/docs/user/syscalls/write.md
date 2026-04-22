
`write` syscall
===============

```C
ssize_t write(fd_t file, void *src, size_t size);
```

# Overview
Write to `file` starting at the current seek offset.
Depending on the underlying file type, advances the
seek offset by the amount written.

# Arguments

`file`: index of the file descriptor to write to.

`src`: buffer of at least length `size` to write data from.

`size`: the maximum number of bytes to write.

# Return Value
On success, returns the positive number of bytes written.
If `0` is returned, the "end-of-file" condition is asserted.
Otherwise a negative errno value is returned.
