
.text

.macro syscall __name __num
.global kanawha_sys_\__name
.type kanawha_sys_\__name, @function
kanawha_sys_\__name:
    li a7, \__num
    ecall
    ret
.endm

SYSCALL exit      , 0
SYSCALL open      , 1
SYSCALL close     , 2
SYSCALL read      , 3
SYSCALL write     , 4
SYSCALL seek      , 5
SYSCALL flush     , 6
SYSCALL mmap      , 7
SYSCALL munmap    , 8
SYSCALL exec      , 9
SYSCALL environ   , 10
SYSCALL getcwd    , 11
SYSCALL spawn     , 12
SYSCALL reap      , 13
SYSCALL faccess   , 14
SYSCALL mount     , 15
SYSCALL unmount   , 16
SYSCALL dirbegin  , 17
SYSCALL dirnext   , 18
SYSCALL dirattr   , 19
SYSCALL dirname   , 20
SYSCALL fmove     , 21
SYSCALL fattr     , 22
SYSCALL mkfile    , 23
SYSCALL mkdir     , 24
SYSCALL link      , 25
SYSCALL symlink   , 26
SYSCALL unlink    , 27
SYSCALL chroot    , 28
SYSCALL pipe      , 29
SYSCALL insmod    , 30
SYSCALL rmmod     , 31
SYSCALL chwdir    , 32
SYSCALL sleep     , 33
SYSCALL time      , 34
SYSCALL rid       , 37
SYSCALL wid       , 38
SYSCALL resize    , 39
SYSCALL poll      , 40
SYSCALL sigsend   , 41
SYSCALL siginfo   , 42
SYSCALL sigmod    , 43
SYSCALL prget     , 44
SYSCALL prset     , 45
SYSCALL connect   , 46
SYSCALL accept    , 47
SYSCALL socket    , 48
SYSCALL mwait     , 49
SYSCALL mwake     , 50

