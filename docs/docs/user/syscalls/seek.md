
`seek` syscall
==============

```C
ssize_t seek(fd_t file, ssize_t offset, int whence);
```

# Overview
Change a file's seek offset.

# Argument

`file`: index of the file descriptor whose seek offset we will change.

`offset`: meaning depends on `whence`.

`whence`: one of the following values

- `SEEK_SET`: overwrite the file seek offset with `offset`.
- `SEEK_CUR`: add `offset` to the file's current seek offset.
- `SEEK_END`: add `offset` to the greatest valid seek offset of the file and set the file's seek offset to that value.

# Return Value
If the return value is `>=0` then it is the file descriptor's
new seek offset. Otherwise it is a negative errno value and
the file's seek offset should be left unchanged.
