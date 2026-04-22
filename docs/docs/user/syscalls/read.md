
`read` syscall
==============

```C
ssize_t read(fd_t file, void *src, size_t size);
```

# Overview
Read from `file` starting at the current seek offset.
Depending on the underlying file type, advances the
seek offset by the amount read.

# Arguments

`file`: index of the file descriptor to read from.

`src`: buffer of at least length `size` to write data into.

`size`: the maximum number of bytes to read from the file.

# Return Value
On success, returns the positive number of bytes read.
If `0` is returned, the "end-of-file" condition is asserted.
Otherwise a negative errno value is returned.

