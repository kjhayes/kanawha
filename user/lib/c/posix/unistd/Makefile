
obj-y += \
	close.o \
	fork.o \
	vfork.o \
	dup.o \
	dup2.o \
	pipe.o \
	chdir.o \
	chroot.o \
	execv.o \
	execl.o \
	execve.o \
	execvp.o \
	sleep.o \
	alarm.o \
	usleep.o \
	unlink.o \
	getcwd.o \
	write.o \
	read.o \
	access.o \
	lseek.o \
	isatty.o \
	fsync.o \
	link.o \
	symlink.o \
	readlink.o \
	ftruncate.o \
	getpid.o \
	getppid.o \
	getuid.o \
	geteuid.o \
	getgid.o \
	getegid.o \
	getpgid.o \
	setpgid.o \
	getpgrp.o \
	tcgetpgrp.o \
	tcsetpgrp.o \
	getgroups.o \
	getlogin.o \

obj-$(CONFIG_X64) += x64_fork_impl.o
obj-$(CONFIG_RISCV64) += riscv64_fork_impl.o
obj-$(CONFIG_ARM64) += arm64_fork_impl.o
