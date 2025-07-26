
Init Stages
===========

Kernel initialization is broken down into a number of
stages, which have a different set of capabilties as more
of the kernel is started running.

These stages are defined in `kanawha/init.h`.

To add an initialization function such as
```
static int my_function(void) {
    return 0;
}
```
include `kanawha/init.h` and add
```
declare_init(STAGE, my_function);
```
or
```
declare_init_desc(STAGE, my_function, "A description of my function");
```

An initialization function must return zero on success
or a negative errno on failure.

Failure of an initialization function will cause a kernel panic at boot.

## Dependencies within a Stage

Returning the special errno `-EDEFER` will cause the kernel to re-attempt
an init function at the end of the current stage.

If no function which originally deferred completes successfully then a kernel panic will occur.
Otherwise, the kernel will keep attempting to run the init
functions as long as it is making progress.

