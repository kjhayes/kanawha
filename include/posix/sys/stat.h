#ifndef __ELK_POSIX__STAT_H__
#define __ELK_POSIX__STAT_H__

#include <sys/types.h>
#include <elk-libc-internal/timespec.h>

struct stat {
    dev_t     st_dev;     // ID of device containing file
    ino_t     st_ino;     // file serial number
    mode_t    st_mode;    // mode of file (see below)
    nlink_t   st_nlink;   // number of links to the file
    uid_t     st_uid;     // user ID of file
    gid_t     st_gid;     // group ID of file
    dev_t     st_rdev;    // device ID (if file is character or block special)
    off_t     st_size;    // file size in bytes (if file is a regular file)

    struct timespec st_atim; // last access
    struct timespec st_mtim; // last data modification
    struct timespec st_ctim; // last status change

#define st_atime st_atim.tv_sec
#define st_mtime st_mtim.tv_sec
#define st_ctime st_ctim.tv_sec

    blksize_t st_blksize; // a filesystem-specific preferred I/O block size for
                          // this object.  In some filesystem types, this may
                          // vary from file to file
    blkcnt_t  st_blocks;  // number of blocks allocated for this object
};

// File Type
#define S_IFMT   (0170000)
#define S_IFBLK  (0060000)
#define S_IFCHR  (0020000)
#define S_IFIFO  (0010000)
#define S_IFDIR  (0040000)
#define S_IFREG  (0100000)
#define S_IFLNK  (0120000)
#define S_IFSOCK (0140000)

// File mode
#define S_IRUSR (00400)
#define S_IWUSR (00200)
#define S_IXUSR (00100)
#define S_IRGRP (00040)
#define S_IWGRP (00020)
#define S_IXGRP (00010)
#define S_IROTH (00004)
#define S_IWOTH (00002)
#define S_IXOTH (00001)
#define S_ISUID (04000)
#define S_ISGID (02000)
#define S_ISVTX (01000)

#define S_IRWXU (S_IRUSR|S_IWUSR|S_IXUSR)
#define S_IRWXG (S_IRGRP|S_IWGRP|S_IXGRP)
#define S_IRWXO (S_IROTH|S_IWOTH|S_IXOTH)

#define S_ISBLK(m)    ((m & S_IFBLK) == S_IFBLK)
#define S_ISCHR(m)    ((m & S_IFCHR) == S_IFCHR)   
#define S_ISDIR(m)    ((m & S_IFDIR) == S_IFDIR)
#define S_ISFIFO(m)   ((m & S_IFIFO) == S_IFIFO)
#define S_ISREG(m)    ((m & S_IFREG) == S_IFREG)
#define S_ISLNK(m)    ((m & S_IFLNK) == S_IFLNK)
#define S_ISSOCK(m)    ((m & S_IFSOCK) == S_IFSOCK)

#define S_TYPEISMQ(buf)  (0)
#define S_TYPEISSEM(buf) (0)
#define S_TYPEISSHM(buf) (0)

int    chmod(const char *, mode_t);
int    fchmod(int, mode_t);
int    fstat(int, struct stat *);
int    lstat(const char *, struct stat *);
int    mkdir(const char *, mode_t);
int    mkfifo(const char *, mode_t);
int    mknod(const char *, mode_t, dev_t);
int    stat(const char *, struct stat *);
mode_t umask(mode_t);

#endif
