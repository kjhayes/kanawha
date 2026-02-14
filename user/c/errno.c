
static int __errno = 0;

int *
__elk_errno(void) {
    return &__errno;
}

